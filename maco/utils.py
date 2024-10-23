# Common utilities shared between the MACO collector and configextractor-py
import importlib
import inspect
import json
import os
import pkgutil
import shutil
import subprocess
import sys
import tempfile

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from base64 import b64decode
from glob import glob
from logging import Logger
from sys import executable as python_exe
from typing import Any, Callable, Tuple, Dict
from types import ModuleType

from maco.extractor import Extractor


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
        rpaths = []
        dependencies = []

        for req_file in list({"requirements.txt", "pyproject.toml"}.intersection(set(files))):
            rpath = os.path.join(root, req_file)
            rpaths.append(rpath)
            with open(rpath, "r") as f:
                if req_file == "requirements.txt":
                    # Parse requirements.txt file to retrieve dependencies
                    dependencies.extend([d for d in f.read().splitlines() if d and not d.startswith("#")])
                elif req_file == "pyproject.toml":
                    # Parse TOML file to retrieve the dependencies
                    # Ref: https://packaging.python.org/en/latest/guides/writing-pyproject-toml/#dependencies-and-requirements

                    parsed_toml_project = tomllib.loads(f.read()).get("project", {})

                    if "dependencies" in parsed_toml_project:
                        # Retrieve required dependencies
                        dependencies.extend(parsed_toml_project["dependencies"])

                    if "optional-dependencies" in parsed_toml_project:
                        # Retrieve optional dependencies
                        optional_dependencies = parsed_toml_project["optional-dependencies"]
                        if isinstance(optional_dependencies, list):
                            # Flat list of optional dependencies
                            dependencies.extend(optional_dependencies)

                        elif isinstance(optional_dependencies, dict):
                            # Map of dependencies, install them all for good measure
                            for dependencies_list in optional_dependencies.values():
                                dependencies.extend(dependencies_list)

        if dependencies:
            venv_path = os.path.join(root, "venv")
            # Create a venv environment if it doesn't already exist
            if not os.path.exists(venv_path):
                logger.info(f"Creating venv at: {venv_path}")
                subprocess.run([python_exe, "-m", "venv", venv_path], capture_output=True)

            # Install/Update packages within the venv relative the dependencies extracted
            logger.debug(f"Packages to be installed: {dependencies}")
            p = subprocess.run(
                ["venv/bin/pip", "install", "-U"] + dependencies + ["--disable-pip-version-check"],
                cwd=root,
                capture_output=True,
            )

            if p.stderr:
                if b"is being installed using the legacy" in p.stderr:
                    # Ignore these types of errors
                    continue
                logger.error(f"Error installing {rpaths} into venv:\n{p.stderr.decode()}")
            logger.debug(f"Installed {rpaths} into venv:\n{p.stdout}")
        elif rpaths:
            logger.warning(f"No dependencies extracted from project files: {rpaths}..")

        if root == root_directory and not recurse:
            # Limit venv creation to the root directory
            break


def find_extractors(
    parsers_dir: str,
    logger: Logger,
    extractor_module_callback: Callable[[ModuleType, ModuleType, str], bool],
):
    parsers_dir = os.path.abspath(parsers_dir)
    logger.debug("Adding directories within parser directory in case of local dependencies")
    logger.debug(f"Adding {os.path.join(parsers_dir, os.pardir)} to PATH")

    # Specific feature for Assemblyline or environments wanting to run parsers from different sources
    # The goal is to try and introduce package isolation/specification similar to a virtual environment when running parsers
    root_venv = None
    if "venv" in os.listdir(parsers_dir):
        root_venv = os.path.join(parsers_dir, "venv")

    # Find extractors (taken from MaCo's Collector class)
    path_parent, foldername = os.path.split(parsers_dir)
    original_dir = parsers_dir
    sys.path.insert(1, path_parent)
    sys.path.insert(1, parsers_dir)
    if "src" in os.listdir(parsers_dir):
        # The actual module might be located in the src subdirectory
        # Ref: https://packaging.python.org/en/latest/discussions/src-layout-vs-flat-layout/
        src_path = os.path.join(parsers_dir, "src")
        sys.path.insert(1, src_path)

        # The module to be loaded should be the directory within src
        foldername = [d for d in os.listdir(src_path) if os.path.isdir(os.path.join(src_path, d))][0]

    if root_venv:
        # Insert the venv's site-packages into the PATH temporarily to load the module
        for dir in glob(os.path.join(root_venv, "lib/python*/site-packages")):
            sys.path.insert(2, dir)
            break
        mod = importlib.import_module(foldername)
        sys.path.pop(2)
    else:
        mod = importlib.import_module(foldername)

    if mod.__file__ and not mod.__file__.startswith(parsers_dir):
        # Library confused folder name with installed package
        sys.path.remove(path_parent)
        sys.path.remove(parsers_dir)
        parsers_dir = tempfile.TemporaryDirectory().name
        shutil.copytree(original_dir, parsers_dir, dirs_exist_ok=True)

        path_parent, foldername = os.path.split(parsers_dir)
        sys.path.insert(1, path_parent)
        sys.path.insert(1, parsers_dir)
        mod = importlib.import_module(foldername)

    # walk packages in the extractors directory to find all extactors
    for module_path, module_name, ispkg in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):

        def find_venv(path: str) -> str:
            parent_dir = os.path.dirname(path)
            if "venv" in os.listdir(path):
                # venv is in the same directory as the parser
                return os.path.join(path, "venv")
            elif parent_dir == parsers_dir or path == parsers_dir:
                # We made it all the way back to the parser directory
                # Use root venv, if any
                return root_venv
            elif "venv" in os.listdir(parent_dir):
                # We found a venv before going back to the root of the parser directory
                # Assume that because it's the closest, it's the most relevant
                return os.path.join(parent_dir, "venv")
            else:
                # Keep searching in the parent directory for a venv
                return find_venv(parent_dir)

        if ispkg:
            # skip __init__.py
            continue

        if module_name.endswith(".setup"):
            # skip setup.py
            continue

        logger.debug(f"Inspecting '{module_name}' for extractors")

        # Local site packages, if any, need to be loaded before attempting to import the module
        parser_venv = find_venv(module_path.path)
        parser_site_packages = None
        if parser_venv:
            for dir in glob(os.path.join(parser_venv, "lib/python*/site-packages")):
                sys.path.insert(1, dir)
                break

        try:
            module = importlib.import_module(module_name)
        except Exception as e:
            # Log if there was an error importing module
            logger.error(f"{module_name}: {e}")
            continue
        finally:
            if parser_site_packages in sys.path:
                sys.path.remove(parser_site_packages)
        # Determine if module contains parsers of a supported framework
        candidates = [module] + [member for _, member in inspect.getmembers(module) if inspect.isclass(member)]
        for member in candidates:
            try:
                if member.__name__ == module.__name__:
                    # Account for the possibility of multiple extractor classes within the same module
                    continue

                if extractor_module_callback(member, module, parser_venv):
                    # If the callback returns with a positive response, we can move onto the next module
                    break

            except TypeError:
                pass
            except Exception as e:
                logger.error(f"{member}: {e}")

    if original_dir != parsers_dir:
        # Correct the paths to the parsers to match metadata changes
        sys.path.remove(path_parent)
        sys.path.remove(parsers_dir)
        path_parent, _ = os.path.split(original_dir)
        sys.path.insert(1, path_parent)
        sys.path.insert(1, original_dir)
        shutil.rmtree(parsers_dir)


def run_in_venv(
    sample_path, module, module_path, venv, root_directory, venv_script=VENV_SCRIPT, json_decoder=Base64Decoder
) -> Dict[str, dict]:
    # Write temporary script in the same directory as extractor to resolve relative imports
    python_exe = os.path.join(venv, "bin", "python")
    dirname = os.path.dirname(module_path)
    with tempfile.NamedTemporaryFile("w", dir=dirname, suffix=".py") as script:
        with tempfile.NamedTemporaryFile() as output:
            module_name = module.__module__
            module_class = module.__name__
            parent_package_path = dirname.rsplit(module_name.split(".", 1)[0], 1)[0]

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
            custom_module = script.name.split(".py")[0].replace(f"{root_directory}/", "").replace("/", ".")

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
