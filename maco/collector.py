"""Convenience functions for discovering your extractors."""

import inspect
import logging
import os
from multiprocessing import Manager, Process
from tempfile import NamedTemporaryFile
from types import ModuleType
from typing import Any, BinaryIO, Dict, List, Union

from pydantic import BaseModel

from maco import extractor, model, utils, yara


class ExtractorLoadError(Exception):
    pass


logger = logging.getLogger("maco.lib.helpers")


def _verify_response(resp: Union[BaseModel, dict]) -> Dict:
    """Enforce types and verify properties, and remove defaults."""
    if not resp:
        return None
    # check the response is valid for its own model
    # this is useful if a restriction on the 'other' dictionary is needed
    resp_model = type(resp)
    if resp_model != model.ExtractorModel and hasattr(resp_model, "model_validate"):
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
        path_extractors = os.path.realpath(path_extractors)
        self.path: str = path_extractors
        self.extractors: Dict[str, Dict[str, str]] = {}

        with Manager() as manager:
            extractors = manager.dict()
            namespaced_rules = manager.dict()

            def extractor_module_callback(module: ModuleType, venv: str):
                members = inspect.getmembers(module, predicate=utils.maco_extractor_validation)
                for member in members:
                    name, member = member
                    if exclude and name in exclude:
                        # Module is part of the exclusion list, skip
                        logger.debug(f"exclude excluded '{name}'")
                        return

                    if include and name not in include:
                        # Module wasn't part of the inclusion list, skip
                        logger.debug(f"include excluded '{name}'")
                        return

                    # initialise and register
                    logger.debug(f"register '{name}'")
                    extractors[name] = dict(
                        venv=venv,
                        module_path=module.__file__,
                        module_name=member.__module__,
                        extractor_class=member.__name__,
                    )
                    namespaced_rules[name] = member.yara_rule or extractor.DEFAULT_YARA_RULE.format(name=name)

            # Find the extractors within the given directory
            # Execute within a child process to ensure main process interpreter is kept clean
            p = Process(
                target=utils.import_extractors,
                args=(
                    path_extractors,
                    yara.compile(source=utils.MACO_YARA_RULE),
                    extractor_module_callback,
                    logger,
                    create_venv and os.path.isdir(path_extractors),
                ),
            )
            p.start()
            p.join()

            self.extractors = dict(extractors)
            if not self.extractors:
                raise ExtractorLoadError("no extractors were loaded")
            logger.debug(f"found extractors {list(self.extractors.keys())}\n")

            # compile yara rules gathered from extractors
            self.rules = yara.compile(sources=dict(namespaced_rules))

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
        try:
            # Run extractor on a copy of the sample
            with NamedTemporaryFile() as sample_path:
                sample_path.write(stream.read())
                sample_path.flush()
                # enforce types and verify properties, and remove defaults
                return _verify_response(utils.run_extractor(sample_path.name, **extractor))
        except Exception:
            # caller can deal with the exception
            raise
        finally:
            # make sure to reset where we are in the file
            # otherwise follow on extractors are going to read 0 bytes
            stream.seek(0)
