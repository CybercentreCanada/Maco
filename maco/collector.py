"""Convenience functions for discovering your extractors."""

import logging
import os

from tempfile import NamedTemporaryFile
from typing import Any, BinaryIO, Dict, List

import yara
from pydantic import BaseModel

from maco import extractor, model, utils


class ExtractorLoadError(Exception):
    pass


logger = logging.getLogger("maco.lib.helpers")


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
        self.extractors = {}
        namespaced_rules = {}

        if create_venv and os.path.isdir(path_extractors):
            # Recursively create/update virtual environments
            utils.create_venv(path_extractors, logger=logger)

        def extractor_module_callback(member, module, venv) -> bool:
            name = member.__name__
            if exclude and name in exclude:
                # Module is part of the exclusion list, skip
                logger.debug(f"exclude excluded '{name}'")
                return

            if include and name not in include:
                # Module wasn't part of the inclusion list, skip
                logger.debug(f"include excluded '{name}'")
                return

            if utils.maco_extractor_validation(member):
                # check if we want this extractor

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
                # Run extractor within a virtual environment
                with NamedTemporaryFile() as sample_path:
                    sample_path.write(stream.read())
                    sample_path.flush()
                    return utils.run_in_venv(sample_path.name, **extractor)
            else:
                # Run extractor within on host environment
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
