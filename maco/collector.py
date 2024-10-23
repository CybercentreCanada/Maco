"""Convenience functions for discovering your extractors."""

import importlib
import inspect
import json
import logging
import os
import pkgutil
import subprocess
import sys

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from base64 import b64decode
from glob import glob
from sys import executable as python_exe
from tempfile import NamedTemporaryFile
from typing import Any, BinaryIO, Dict, List

import yara
from pydantic import BaseModel

from maco import extractor, model, utils


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
        self.extractors = {}
        namespaced_rules = {}

        if create_venv and os.path.isdir(path_extractors):
            # Recursively create/update virtual environments
            utils.create_venv(path_extractors, logger=logger)

        def extractor_module_callback(member, module, venv) -> bool:
            if utils.maco_extractor_validation(member):
                # check if we want this extractor
                name = member.__name__
                if self.exclude and name in self.exclude:
                    logger.debug(f"exclude excluded '{name}'")
                    return
                if self.include and name not in self.include:
                    logger.debug(f"include excluded '{name}'")
                    return
                # initialise and register
                logger.debug(f"register '{name}'")
                self.extractors[name] = dict(module=member, venv=venv, module_path=module.__file__)
                namespaced_rules[name] = member.yara_rule or extractor.DEFAULT_YARA_RULE.format(name=name)
                return True

        # Find the extractors within the given directory
        utils.find_extractors(path_extractors, logger=logger, extractor_module_callback=extractor_module_callback)

        if not self.extractors:
            raise ExtractorLoadError("no extractors were loaded")
        logger.debug(f"found extractors {list(self.extractors.keys())}\n")

        # compile yara rules gathered from extractors
        self.rules = yara.compile(sources=namespaced_rules)

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
            runs.setdefault(match.namespace, []).append(match)

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
                with NamedTemporaryFile() as sample_path:
                    sample_path.write(stream.read())
                    sample_path.flush()
                    resp = utils.run_in_venv(sample_path.name, **extractor, root_directory=self.path)
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
