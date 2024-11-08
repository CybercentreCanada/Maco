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
from pkgutil import walk_packages
from typing import Callable, Dict, Tuple, List, Set
from types import ModuleType

from maco.extractor import Extractor

VENV_DIRECTORY_NAME = ".venv"


try:
    # Attempt to use the uv package manager (Recommended)
    from uv import find_uv_bin

    UV_BIN = find_uv_bin()

    PIP_CMD = f"{UV_BIN} pip"
    VENV_CREATE_CMD = f"{UV_BIN} venv"
    PACKAGE_MANAGER = "uv"
except ImportError:
    # Otherwise default to pip
    from sys import executable

    PIP_CMD = "pip"
    VENV_CREATE_CMD = f"{executable} -m venv"
    PACKAGE_MANAGER = "pip"

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
        $class = /class \w+\(([a-zA-Z.]+)?Extractor\)\:/
    condition:
        ($from or $import) and $extractor and $class
}
"""


def maco_extractor_validation(module: ModuleType) -> bool:
    if inspect.isclass(module):
        # 'author' has to be implemented otherwise will raise an exception according to MACO
        return bool(issubclass(module, Extractor) and module.author)
    return False


def maco_extract_rules(module: Extractor) -> bool:
    return module.yara_rule


def scan_for_extractors(root_directory: str, scanner: yara.Rules, logger: Logger) -> Tuple[List[str], List[str]]:
    extractor_dirs = set([root_directory])
    extractor_files = []

    # Search for extractors using YARA rules
    logger.info("Searching for prospective extractors based on YARA rules..")
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
    return extractor_dirs, extractor_files


def create_virtual_environments(directories: List[str], stop_directory: str, python_version: str, logger: Logger):
    venvs = []
    logger.info("Creating virtual environment(s)..")
    env = deepcopy(os.environ)
    # Track directories that we've already visited
    visited_dirs = []
    for dir in directories:
        # Recurse backwards through the directory structure to look for package requirements
        while dir != stop_directory and dir not in visited_dirs:
            req_files = list({"requirements.txt", "pyproject.toml"}.intersection(set(os.listdir(dir))))
            if req_files:
                venv_path = os.path.join(dir, VENV_DIRECTORY_NAME)
                env.update({"VIRTUAL_ENV": venv_path})
                # Create a virtual environment for the directory
                if not os.path.exists(venv_path):
                    cmd = VENV_CREATE_CMD
                    if PACKAGE_MANAGER == "uv":
                        cmd += f" --python {python_version}"
                    subprocess.run(cmd.split(" ") + [venv_path], capture_output=True, env=env)

                # Install/Update the packages in the environment
                install_command = PIP_CMD.split(" ") + ["install", "-U"]

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

                logger.debug(f"Install command: {' '.join(install_command)} [{dir}]")
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
    return venvs


def find_and_insert_venv(path: str, venvs: List[str]):
    venv = None
    for venv in sorted(venvs, reverse=True):
        venv_parent = os.path.dirname(venv)
        if path.startswith(venv_parent):
            # Found the virtual environment that's the closest to extractor
            break

    if not venv:
        return None, None

    if venv:
        # Insert the venv's site-packages into the PATH temporarily to load the module
        for site_package in glob(os.path.join(venv, "lib/python*/site-packages")):
            if site_package not in sys.path:
                sys.path.insert(2, site_package)
            break

    return venv, site_package


def register_extractors(
    current_directory: str,
    venvs: List[str],
    extractor_files: List[str],
    extractor_module_callback: Callable[[ModuleType, str], None],
    logger: Logger,
    default_loaded_modules: Set[str] = set(sys.modules.keys()),
):
    package_name = os.path.basename(current_directory)
    parent_directory = os.path.dirname(current_directory)
    symlink = None
    while package_name in sys.modules:
        # Package name conflicts with an existing loaded module, let's deconflict that
        package_name = f"_{package_name}"

        # We'll need to create a link back to the original
        if package_name not in sys.modules:
            symlink = os.path.join(parent_directory, package_name)
            os.symlink(current_directory, symlink)

    try:
        # Modify the PATH so we can recognize this new package on import
        sys.path.insert(1, current_directory)
        sys.path.insert(1, parent_directory)

        # Insert any virtual environment necessary to load directory as package
        package_venv, package_site_packages = find_and_insert_venv(current_directory, venvs)
        package = importlib.import_module(package_name)

        # Walk through our new package and find the extractors that YARA identified
        for module_path, module_name, ispkg in walk_packages(package.__path__, package.__name__ + "."):
            if ispkg:
                # Skip packages
                continue

            module_path = os.path.realpath(os.path.join(module_path.path, module_name.rsplit(".", 1)[1]) + ".py")
            if module_path in extractor_files:
                # Cross this extractor off the list of extractors to find
                logger.debug(f"Inspecting '{module_name}' for extractors..")
                extractor_files.remove(module_path)
                try:
                    # This is an extractor we've been looking for, load the module and invoke callback
                    venv, site_packages = find_and_insert_venv(module_path, venvs)
                    module = importlib.import_module(module_name)
                    module.__file__ = os.path.realpath(module.__file__)
                    extractor_module_callback(module, venv)
                finally:
                    # Cleanup virtual environment that was loaded into PATH
                    if venv and site_packages in sys.path:
                        sys.path.remove(site_packages)

    finally:
        # Cleanup changes made to PATH
        sys.path.remove(parent_directory)
        sys.path.remove(current_directory)

        if package_venv and package_site_packages in sys.path:
            sys.path.remove(package_site_packages)

        # Remove any modules that were loaded to deconflict with later modules loads
        [sys.modules.pop(k) for k in set(sys.modules.keys()) - default_loaded_modules]

        # Cleanup any symlinks
        if symlink:
            os.remove(symlink)

    # If there still exists extractor files we haven't found yet, try searching in the available subdirectories
    if extractor_files:
        for dir in os.listdir(current_directory):
            path = os.path.join(current_directory, dir)
            if dir == "__pycache__":
                # Ignore the cache created
                continue
            elif dir.endswith(".egg-info"):
                # Ignore these directories
                continue
            elif dir.startswith("."):
                # Ignore hidden directories
                continue

            if os.path.isdir(path):
                # Check subdirectory to find the rest of the detected extractors
                register_extractors(
                    path, venvs, extractor_files, extractor_module_callback, logger, default_loaded_modules
                )

            if not extractor_files:
                # We were able to find all the extractor files
                break


def import_extractors(
    root_directory: str,
    scanner: yara.Rules,
    extractor_module_callback: Callable[[ModuleType, str], bool],
    logger: Logger,
    create_venv: bool = False,
    python_version: str = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
):
    extractor_dirs, extractor_files = scan_for_extractors(root_directory, scanner, logger)

    logger.info(f"Extractor files found based on scanner ({len(extractor_files)}).")
    logger.debug(extractor_files)

    venvs = []
    root_parent = os.path.dirname(root_directory)
    if create_venv:
        venvs = create_virtual_environments(extractor_dirs, root_parent, python_version, logger)
    else:
        # Look for pre-existing virtual environments, if any
        logger.info("Checking for pre-existing virtual environment(s)..")
        venvs = [
            os.path.join(root, VENV_DIRECTORY_NAME)
            for root, dirs, _ in os.walk(root_directory)
            if VENV_DIRECTORY_NAME in dirs
        ]

    # With the environment prepared, we can now hunt for the extractors and register them
    logger.info("Registering extractors..")
    register_extractors(root_directory, venvs, extractor_files, extractor_module_callback, logger)


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
