"""Convenience functions for discovering your extractors."""
import importlib
import inspect
import json
import logging
import os
import pkgutil
import subprocess
import sys
from base64 import b64decode
from glob import glob
from sys import executable as python_exe
from tempfile import NamedTemporaryFile
from typing import Any, BinaryIO, Dict, List

import yara
from pydantic import BaseModel

from . import extractor, model


class ExtractorLoadError(Exception):
    pass


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


logger = logging.getLogger("maco.lib.helpers")


VENV_SCRIPT = """
import importlib
import json
import os
import sys
import yara

from base64 import b64encode
parent_package_path = os.path.dirname(__file__).rsplit("{module_name}".split('.', 1)[0], 1)[0]
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


def _verify_response(resp: BaseModel) -> Dict:
    """Enforce types and verify properties, and remove defaults."""
    # check the response is valid for its own model
    # this is useful if a restriction on the 'other' dictionary is needed
    resp_model = type(resp)
    if resp_model != model.ExtractorModel:
        resp = resp_model.model_validate(resp)
    # check the response is valid according to the ExtractorModel
    resp = model.ExtractorModel.model_validate(resp)
    # coerce sets to correct types
    # otherwise we end up with sets where we expect lists
    resp = model.ExtractorModel(**resp.model_dump())
    # dump model to dict
    return resp.model_dump(exclude_defaults=True)


class Collector:
    def __init__(
        self, path_extractors: str, include: List[str] = None, exclude: List[str] = None, create_venv: bool = False
    ):
        """Discover and load extractors from file system."""
        self.path = path_extractors
        self.include = include
        self.exclude = exclude

        if create_venv and os.path.isdir(path_extractors):
            for root, _, files in os.walk(path_extractors):
                if "requirements.txt" in files:
                    # Create venv
                    venv_path = os.path.join(root, "venv")
                    logger.debug(f"creating venv at: {venv_path}")
                    subprocess.run([python_exe, "-m", "venv", venv_path], capture_output=True)
                    p = subprocess.run(
                        ["venv/bin/pip", "install", "-r", "requirements.txt", "--disable-pip-version-check"],
                        cwd=root,
                        capture_output=True,
                    )
                    rpath = os.path.join(root, "requirements.txt")
                    if p.stderr:
                        logger.error(f"error installing {rpath} into venv:\n{p.stderr}")
                    logger.debug(f"installed {rpath} into venv:\n{p.stdout}")

        self.extractors = self._find_extractors()

        # compile yara rules gathered from extractors
        rules_merged = "\n".join([x["module"].yara_rule or "" for x in self.extractors.values()])
        self.rules = yara.compile(source=rules_merged)

        # map rule names to extractors, since each extractor can have multiple rules
        self.rule_map = {}
        for k, v in self.extractors.items():
            self.rule_map.update({r: k for r in v["module"]().yara_rule_names})

    def _find_extractors(self):
        """Find extractors from the supplied path."""

        self.path = os.path.abspath(self.path)
        filename = ""
        if os.path.isfile(self.path):
            # assume python script .py
            self.path, filename = os.path.split(self.path)
            filename = os.path.splitext(filename)[0]
        elif not os.path.isdir(self.path):
            raise ExtractorLoadError(f"path is not file or folder: {self.path=}")
        # dynamic import of extractors
        path_parent, foldername = os.path.split(self.path)
        # add to near front of path to win name collisions
        sys.path.insert(1, path_parent)
        sys.path.insert(1, self.path)
        logger.debug(f"{path_parent=}")
        logger.debug(f"{foldername=}")
        logger.debug(f"{sys.path=}")
        mod = importlib.import_module(foldername)

        root_venv = None
        if "venv" in os.listdir(self.path):
            root_venv = os.path.join(self.path, "venv")

        def find_venv(path: str) -> str:
            parent_dir = os.path.dirname(path)
            if "venv" in os.listdir(path):
                # venv is in the same directory as the parser
                return os.path.join(path, "venv")
            elif parent_dir == self.path or path == self.path:
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

        # walk packages in the extractors directory to find all extactors
        extractors = {}
        for module_path, module_name, ispkg in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):
            if ispkg:
                # skip __init__.py
                continue
            if not module_name.endswith(filename):
                # if filename was specified, skip modules that don't have that name
                continue
            logger.debug(f"inspecting '{module_name}' for extractors")
            # raise an exception if one of the potential extractors can't be imported
            # note that excluding an extractor through include/exclude does not prevent it being imported

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

            # find extractors in the module
            for _, member in inspect.getmembers(module):
                if not inspect.isclass(member):
                    # not a class
                    continue
                if not issubclass(member, extractor.Extractor):
                    # not an extractor
                    continue
                if issubclass(member, extractor.Extractor) and not member.author:
                    # not a valid extractor
                    continue

                # check if we want this extractor
                name = member.__name__
                if self.exclude and name in self.exclude:
                    logger.debug(f"exclude excluded '{name}'")
                    continue
                if self.include and name not in self.include:
                    logger.debug(f"include excluded '{name}'")
                    continue
                # initialise and register
                logger.debug(f"register '{name}'")
                extractors[name] = dict(module=member, venv=parser_venv, module_path=module_path.path)
        logger.debug(f"found extractors {list(extractors.keys())}\n")
        if not extractors:
            raise ExtractorLoadError("no extractors were loaded")
        return extractors

    def match(self, stream: BinaryIO) -> Dict[str, List[yara.Match]]:
        """Return extractors that should run based on yara rules."""
        # execute yara rules on file to find extractors we should run
        # yara can't run on a stream so we give it a bytestring
        matches = self.rules.match(data=stream.read())
        stream.seek(0)
        if not matches:
            return
        # get all rules that hit for each extractor
        runs = {}
        for match in matches:
            runs.setdefault(self.rule_map[match.rule], []).append(match)

        return runs

    def extract(
        self,
        stream: BinaryIO,
        matches: List[yara.Match],
        extractor_name: str,
    ) -> Dict[str, Any]:
        """Run extractor with stream and verify output matches the model."""
        extractor = self.extractors[extractor_name]
        resp = None
        try:
            if extractor["venv"]:
                # Snippet from configextractor-py

                extractor_module = extractor["module"]
                # Write temporary script in the same directory as extractor to resolve relative imports
                python_exe = os.path.join(extractor["venv"], "bin", "python")
                with NamedTemporaryFile() as sample_path:
                    sample_path.write(stream.read())
                    sample_path.flush()

                    with NamedTemporaryFile("w", dir=extractor["module_path"], suffix=".py") as script:
                        with NamedTemporaryFile() as output:
                            module_name = extractor_module.__module__
                            module_class = extractor_module.__name__
                            script.write(
                                VENV_SCRIPT.format(
                                    module_name=module_name,
                                    module_class=module_class,
                                    sample_path=sample_path.name,
                                    output_path=output.name,
                                )
                            )
                            script.flush()
                            custom_module = script.name.split(".py")[0].replace(f"{self.path}/", "").replace("/", ".")
                            proc = subprocess.run(
                                [python_exe, "-m", custom_module],
                                cwd=self.path,
                                capture_output=True,
                            )
                            try:
                                # Load results and return them
                                output.seek(0)
                                return json.load(output, cls=Base64Decoder)
                            except Exception:
                                # If there was an error raised during runtime, then propagate
                                delim = f'File "{extractor["module_path"]}"'
                                exception = proc.stderr.decode()
                                if delim in exception:
                                    exception = f"{delim}{exception.split(delim, 1)[1]}"
                                raise Exception(exception)
            else:
                resp = extractor["module"]().run(stream, matches)
        except Exception:
            # caller can deal with the exception
            raise
        finally:
            # make sure to reset where we are in the file
            # otherwise follow on extractors are going to read 0 bytes
            stream.seek(0)

        # enforce types and verify properties, and remove defaults
        if resp is not None:
            resp = _verify_response(resp)

        return resp
