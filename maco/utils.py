# Common utilities shared between the MACO collector and configextractor-py
import importlib
import inspect
import json
import os
import pkgutil
import subprocess
import sys
import tempfile

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from base64 import b64decode
from copy import deepcopy
from glob import glob
from logging import Logger
from sys import executable as python_exe
from typing import Callable, Dict
from types import ModuleType

from maco.extractor import Extractor

VENV_DIRECTORY_NAME = ".venv"

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


def maco_extractor_validation(module: ModuleType) -> bool:
    if inspect.isclass(module):
        # 'author' has to be implemented otherwise will raise an exception according to MACO
        return bool(issubclass(module, Extractor) and module.author)
    return False


def maco_extract_rules(module: Extractor) -> bool:
    return module.yara_rule


def create_venv(root_directory: str, logger: Logger, recurse: bool = True):
    # Recursively look for "requirements.txt" or "pyproject.toml" files and create a virtual environment
    for root, _, files in os.walk(root_directory):
        req_files = list({"requirements.txt", "pyproject.toml"}.intersection(set(files)))
        if req_files:
            install_command = [
                f"{VENV_DIRECTORY_NAME}/bin/pip",
                "install",
                "-U",
            ]
            venv_path = os.path.join(root, VENV_DIRECTORY_NAME)
            # Create a venv environment if it doesn't already exist
            if not os.path.exists(venv_path):
                logger.info(f"Creating venv at: {venv_path}")
                subprocess.run([python_exe, "-m", "venv", venv_path], capture_output=True)
                # Update pip
                subprocess.run(
                    [f"{VENV_DIRECTORY_NAME}/bin/pip", "install", "--upgrade", "pip"],
                    capture_output=True,
                    cwd=root,
                )
            else:
                logger.info(f"Updating venv at: {venv_path}")

            # Update the pip install command depending on where the dependencies are coming from
            if "requirements.txt" in req_files:
                # Perform a pip install using the requirements flag
                install_command.extend(["-r", "requirements.txt"])
            elif "pyproject.toml" in req_files:
                # Assume we're dealing with a project directory
                pyproject_command = ["-e", "."]

                # Check to see if there are optional dependencies required
                with open(os.path.join(root, "pyproject.toml"), "rb") as f:
                    parsed_toml_project = tomllib.load(f).get("project", {})
                    for dep_name, dependencies in parsed_toml_project.get("optional-dependencies", {}).items():
                        # Look for the dependency that hints at use of MACO for the extractors
                        if "maco" in " ".join(dependencies):
                            pyproject_command = ["-e", f".[{dep_name}]"]
                            break

                install_command.extend(pyproject_command)

            # Install/Update packages within the venv relative the dependencies extracted
            logger.debug(f"Install command: {' '.join(install_command)}")
            p = subprocess.run(
                install_command,
                cwd=root,
                capture_output=True,
            )
            if p.returncode != 0:
                if b"is being installed using the legacy" in p.stderr:
                    # Ignore these types of errors
                    continue
                logger.error(f"Error installing into venv:\n{p.stderr.decode()}")
            else:
                logger.debug(f"Installed dependencies into venv:\n{p.stdout}")

        if root == root_directory and not recurse:
            # Limit venv creation to the root directory
            break


def find_extractors(
    parsers_dir: str,
    logger: Logger,
    extractor_module_callback: Callable[[ModuleType, ModuleType, str], bool],
):
    original_PATH = deepcopy(sys.path)
    original_modules = set(sys.modules.keys())

    parsers_dir = os.path.abspath(parsers_dir)
    logger.debug("Adding directories within parser directory in case of local dependencies")
    logger.debug(f"Adding {os.path.join(parsers_dir, os.pardir)} to PATH")

    # Specific feature for Assemblyline or environments wanting to run parsers from different sources
    # The goal is to try and introduce package isolation/specification similar to a virtual environment when running parsers
    root_venv = None
    if VENV_DIRECTORY_NAME in os.listdir(parsers_dir):
        root_venv = os.path.join(parsers_dir, VENV_DIRECTORY_NAME)

    # Find extractors (taken from MaCo's Collector class)
    path_parent, foldername = os.path.split(parsers_dir)
    sys.path.insert(1, path_parent)

    def load_module(module_name: str, venv_path: str = None) -> ModuleType:
        if venv_path:
            # Insert the venv's site-packages into the PATH temporarily to load the module
            for dir in glob(os.path.join(venv_path, "lib/python*/site-packages")):
                sys.path.insert(2, dir)
                break
        try:
            return importlib.import_module(module_name)
        except BaseException as e:
            logger.warning(f"Error loading module '{module_name}': {e}")
        finally:
            if venv_path:
                # Cleanup PATH once the module has been loaded (or not)
                sys.path.pop(2)

    # To avoid module confusion, don't add the directory that has the same name as a Python module within to the PATH
    if f"{foldername}.py" not in os.listdir(parsers_dir):
        sys.path.insert(1, parsers_dir)

    if "src" in os.listdir(parsers_dir):
        # The actual module might be located in the src subdirectory
        # Ref: https://packaging.python.org/en/latest/discussions/src-layout-vs-flat-layout/
        src_path = os.path.join(parsers_dir, "src")
        sys.path.insert(1, src_path)

        # The module to be loaded should be the directory within src
        foldername = [
            d for d in os.listdir(src_path) if os.path.isdir(os.path.join(src_path, d)) and not d.endswith(".egg-info")
        ][0]

    symlink = None
    existing_modules = set(INSTALLED_MODULES).union(original_modules)
    while foldername in existing_modules:
        # Prepend foldername with '_' until it doesn't conflict with an already installed package
        foldername = f"_{foldername}"

        if foldername not in existing_modules:
            # Create a symbolic link back to the original directory
            symlink = os.path.join(path_parent, foldername)
            if not os.path.exists(symlink):
                os.symlink(parsers_dir, symlink)

            # Assign the symlink as the target directory parsing to avoid recursion-based errors
            parsers_dir = symlink

    # Load in specified directory as a module for package walking
    mod = load_module(foldername, root_venv)

    def find_venv(path: str) -> str:
        parent_dir = os.path.dirname(path)
        if VENV_DIRECTORY_NAME in os.listdir(path):
            # venv is in the same directory as the parser
            return os.path.join(path, VENV_DIRECTORY_NAME)
        elif parent_dir == parsers_dir or path == parsers_dir:
            # We made it all the way back to the parser directory
            # Use root venv, if any
            return root_venv
        elif VENV_DIRECTORY_NAME in os.listdir(parent_dir):
            # We found a venv before going back to the root of the parser directory
            # Assume that because it's the closest, it's the most relevant
            return os.path.join(parent_dir, VENV_DIRECTORY_NAME)
        else:
            # Keep searching in the parent directory for a venv
            return find_venv(parent_dir)

    # walk packages in the extractors directory to find all extactors
    for module_path, module_name, ispkg in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):

        if ispkg:
            # skip __init__.py
            continue

        if module_name.endswith(".setup"):
            # skip setup.py
            continue

        logger.debug(f"Inspecting '{module_name}' for extractors")

        # Local site packages, if any, need to be loaded before attempting to import the module
        parser_venv = find_venv(module_path.path)
        module = load_module(module_name, parser_venv)
        if not module:
            continue

        # Determine if module contains parsers of a supported framework
        candidates = [module] + [member for _, member in inspect.getmembers(module) if inspect.isclass(member)]
        for member in candidates:
            try:
                if "test" in member.__name__.lower():
                    continue

                # Resolve the real paths before invoking the callback
                module.__file__ = os.path.realpath(module.__file__)
                if parser_venv:
                    parser_venv = os.path.realpath(parser_venv)

                if extractor_module_callback(member, module, parser_venv):
                    # If the callback returns with a positive response, we can move onto the next module
                    break

            except TypeError:
                pass
            except Exception as e:
                logger.error(f"{member}: {e}")

    # Restore PATH to it's original settings and remove any cached modules that was added during this run
    sys.path = original_PATH
    [sys.modules.pop(k) for k in set(sys.modules.keys()) - original_modules]
    if symlink:
        # Cleanup the symlink that was created, it's not needed anymore
        os.remove(symlink)


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
