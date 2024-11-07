# Common utilities shared between the MACO collector and configextractor-py
import importlib
import importlib.machinery
import importlib.util
import inspect
import json
import os
import subprocess
import sys
import tempfile
import yara

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from base64 import b64decode
from copy import deepcopy
from glob import glob
from logging import Logger
from typing import Callable, Dict
from types import ModuleType
from uv import find_uv_bin

from maco.extractor import Extractor

UV_BIN = find_uv_bin()
VENV_DIRECTORY_NAME = ".venv"
PIP_CMD = f"{UV_BIN} pip"
VENV_CREATE_CMD = f"{UV_BIN} venv"

# Intended to help deconflict between system installed packages and extractor directories
INSTALLED_MODULES = [d for d in os.listdir(sys.path[-1]) if not (d.endswith(".py") or d.endswith(".dist-info"))]


class Base64Decoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, obj):
        if "__class__" not in obj:
            return obj
        type = obj["__class__"]
        if type == "bytes":
            return b64decode(obj["data"])
        return obj


VENV_SCRIPT = """
import importlib
import json
import os
import sys
import yara

from base64 import b64encode
parent_package_path = "{parent_package_path}"
sys.path.insert(1, parent_package_path)
mod = importlib.import_module("{module_name}")

class Base64Encoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return dict(__class__="bytes", data=b64encode(o).decode())
        return json.JSONEncoder.default(self, o)
matches = []
if mod.{module_class}.yara_rule:
    matches = yara.compile(source=mod.{module_class}.yara_rule).match("{sample_path}")
result = mod.{module_class}().run(open("{sample_path}", 'rb'), matches=matches)

with open("{output_path}", 'w') as fp:
    if not result:
        json.dump(dict(), fp)
    else:
        try:
            json.dump(result.model_dump(exclude_defaults=True, exclude_none=True), fp, cls=Base64Encoder)
        except AttributeError:
            # venv likely has an older version of Pydantic < 2 installed
            json.dump(result.dict(exclude_defaults=True, exclude_none=True), fp, cls=Base64Encoder)
"""

MACO_YARA_RULE = """
rule MACO {
    meta:
        desc = "Used to match on Python files that contain MACO extractors"
    strings:
        $from = "from maco"
        $import = "import maco"
        $extractor = "Extractor"
    condition:
        ($from or $import) and $extractor
}
"""


def maco_extractor_validation(module: ModuleType) -> bool:
    if inspect.isclass(module):
        # 'author' has to be implemented otherwise will raise an exception according to MACO
        return bool(issubclass(module, Extractor) and module.author)
    return False


def maco_extract_rules(module: Extractor) -> bool:
    return module.yara_rule


def import_extractors(
    root_directory: str,
    scanner: yara.Rules,
    extractor_module_callback: Callable[[ModuleType, str], bool],
    logger: Logger,
    create_venv: bool = False,
):
    extractor_dirs = set([root_directory])
    extractor_files = []

    # Search for extractors using YARA rules
    for root, _, files in os.walk(root_directory):
        if "site-packages" in root:
            # Ignore looking for extractors within packages
            continue

        for file in files:
            if not file.endswith(".py"):
                # Ignore scanning non-Python files
                continue
            elif file in ["setup.py", "__init__.py"]:
                # Ignore setup files and markers for package directories
                continue
            elif "test" in file:
                # Ignore test files
                continue
            elif "deprecated" in file:
                # Ignore deprecated files
                continue

            # Scan Python file for potential extractors
            filepath = os.path.join(root, file)
            if scanner.match(filepath):
                # Add directory to list of hits for venv creation
                extractor_dirs.add(root)
                extractor_files.append(filepath)

    if not extractor_files:
        # No extractor files found
        return

    logger.debug(f"Extractor files found based on scanner: {extractor_files}")

    venvs = []
    root_parent = os.path.dirname(root_directory)
    if create_venv:
        env = deepcopy(os.environ)
        # Track directories that we've already visited
        visited_dirs = []
        for dir in extractor_dirs:
            # Recurse backwards through the directory structure to look for package requirements
            while dir != root_parent and dir not in visited_dirs:
                req_files = list({"requirements.txt", "pyproject.toml"}.intersection(set(os.listdir(dir))))
                if req_files:
                    venv_path = os.path.join(dir, VENV_DIRECTORY_NAME)
                    env.update({"VIRTUAL_ENV": venv_path})
                    # Create a virtual environment for the directory
                    if not os.path.exists(venv_path):
                        subprocess.run(VENV_CREATE_CMD.split(" ") + [venv_path], capture_output=True, env=env)

                    # Install/Update the packages in the environment
                    install_command = PIP_CMD.split(" ") + [
                        "install",
                        "-U",
                        "--python-version",
                        f"{sys.version_info.major}.{sys.version_info.minor}",
                    ]

                    # Update the pip install command depending on where the dependencies are coming from
                    if "requirements.txt" in req_files:
                        # Perform a pip install using the requirements flag
                        install_command.extend(["-r", "requirements.txt"])
                    elif "pyproject.toml" in req_files:
                        # Assume we're dealing with a project directory
                        pyproject_command = ["-e", "."]

                        # Check to see if there are optional dependencies required
                        with open(os.path.join(dir, "pyproject.toml"), "rb") as f:
                            parsed_toml_project = tomllib.load(f).get("project", {})
                            for dep_name, dependencies in parsed_toml_project.get("optional-dependencies", {}).items():
                                # Look for the dependency that hints at use of MACO for the extractors
                                if "maco" in " ".join(dependencies):
                                    pyproject_command = [f".[{dep_name}]"]
                                    break

                        install_command.extend(pyproject_command)

                    logger.debug(f"Install command: {' '.join(install_command)}")
                    p = subprocess.run(
                        install_command,
                        cwd=dir,
                        capture_output=True,
                        env=env,
                    )
                    if p.returncode != 0:
                        if b"is being installed using the legacy" in p.stderr:
                            # Ignore these types of errors
                            continue
                        logger.error(f"Error installing into venv:\n{p.stderr.decode()}")
                    else:
                        logger.debug(f"Installed dependencies into venv:\n{p.stdout.decode()}")
                        venvs.append(venv_path)

                # Add directories to our visited list and check the parent of this directory on the next loop
                visited_dirs.append(dir)
                dir = os.path.dirname(dir)

    # Associate the virtual environments to the supposed extractors, load them, and pass them to the given callback
    # Add root directory into path for any local package imports
    sys.path.insert(1, root_directory)
    sys.path.insert(1, root_parent)
    default_loaded_modules = set(sys.modules.keys())
    for extractor in extractor_files:
        venv = None
        for venv in sorted(venvs, reverse=True):
            if extractor.startswith(venv):
                # Found the virtual environment that's the closest to extractor
                break

        # Try to load the module by using some PATH manipulation
        module = None
        try:
            module_name = os.path.basename(extractor)[:-3]
            symlink = None
            if venv:
                # Insert the venv's site-packages into the PATH temporarily to load the module
                for dir in glob(os.path.join(venv, "lib/python*/site-packages")):
                    sys.path.insert(2, dir)
                    os.environ["PATH"] = f"{dir}:{os.environ['PATH']}"
                    break

            while module_name in default_loaded_modules:
                # The name of this module will conflict with an existing package
                # Let's create a symlink with a different name to deconflict this for loading the module into memory
                module_name = f"_{module_name}"
                if module_name not in default_loaded_modules:
                    symlink = os.path.join(os.path.dirname(extractor, f"{symlink}.py"))
                    os.symlink(extractor, symlink)

            logger.info(f"Loading extractor: {extractor}")
            module_spec = importlib.util.spec_from_file_location(module_name, symlink or extractor)
            module = importlib.util.module_from_spec(module_spec)
            module_spec.loader.exec_module(module)

            # Successfully loaded the module, invoke callback to handle what to do with it
            extractor_module_callback(module, venv)
        except BaseException as e:
            logger.warning(f"Error loading module '{module_name}': {e}")
        finally:
            # Cleanup PATH once the module has been loaded (or not)
            if venv:
                sys.path.pop(2)

            # Remove any modules that were loaded to deconflict with later modules loads
            [sys.modules.pop(k) for k in set(sys.modules.keys()) - default_loaded_modules]

            # Remove any symlinks created on the filesystem
            if symlink:
                os.remove(symlink)
    # Remove root and parent directory from PATH
    sys.path.remove(root_directory)
    sys.path.remove(root_parent)


def run_in_venv(
    sample_path,
    module,
    module_path,
    venv,
    venv_script=VENV_SCRIPT,
    json_decoder=Base64Decoder,
) -> Dict[str, dict]:
    # Write temporary script in the same directory as extractor to resolve relative imports
    python_exe = os.path.join(venv, "bin", "python")
    dirname = os.path.dirname(module_path)
    with tempfile.NamedTemporaryFile("w", dir=dirname, suffix=".py") as script:
        with tempfile.NamedTemporaryFile() as output:
            module_name = module.__module__
            module_class = module.__name__
            parent_package_path = dirname.rsplit(module_name.split(".", 1)[0], 1)[0]
            root_directory = module_path[:-3].rsplit(module_name.split(".", 1)[1].replace(".", "/"))[0]

            script.write(
                venv_script.format(
                    parent_package_path=parent_package_path,
                    module_name=module_name,
                    module_class=module_class,
                    sample_path=sample_path,
                    output_path=output.name,
                )
            )
            script.flush()
            cwd = root_directory
            custom_module = script.name[:-3].replace(root_directory, "").replace("/", ".")

            if custom_module.startswith("src."):
                # src layout found, which means the actual module content is within 'src' directory
                custom_module = custom_module[4:]
                cwd = os.path.join(cwd, "src")

            proc = subprocess.run(
                [python_exe, "-m", custom_module],
                cwd=cwd,
                capture_output=True,
            )
            try:
                # Load results and return them
                output.seek(0)
                return json.load(output, cls=json_decoder)
            except Exception:
                # If there was an error raised during runtime, then propagate
                delim = f'File "{module_path}"'
                exception = proc.stderr.decode()
                if delim in exception:
                    exception = f"{delim}{exception.split(delim, 1)[1]}"
                raise Exception(exception)
