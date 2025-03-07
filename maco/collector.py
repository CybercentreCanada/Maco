"""Convenience functions for discovering your extractors."""

import inspect
import logging
import logging.handlers
import os
import sys
from tempfile import NamedTemporaryFile
from types import ModuleType
from typing import Any, BinaryIO, Dict, List, TypedDict, Union

from multiprocess import Manager, Process, Queue
from pydantic import BaseModel

from maco import extractor, model, utils, yara
from maco.exceptions import AnalysisAbortedException, ExtractorLoadError

logger = logging.getLogger("maco.lib.helpers")


def _verify_response(resp: Union[BaseModel, dict]) -> Dict:
    """Enforce types and verify properties, and remove defaults.

    Args:
        resp (Union[BaseModel, dict])): results from extractor

    Returns:
        (Dict): results from extractor after verification
    """
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


class ExtractorMetadata(TypedDict):
    """Extractor-supplied metadata."""

    author: str
    family: str
    last_modified: str
    sharing: str
    description: str


class ExtractorRegistration(TypedDict):
    """Registration collected by the collector for a single extractor."""

    venv: str
    module_path: str
    module_name: str
    extractor_class: str
    metadata: ExtractorMetadata


class Collector:
    """Discover and load extractors from file system."""

    def __init__(
        self,
        path_extractors: str,
        include: List[str] = None,
        exclude: List[str] = None,
        create_venv: bool = False,
        skip_install: bool = False,
    ):
        """Discover and load extractors from file system.

        Raises:
            ExtractorLoadError: when no extractors are found
        """
        # maco requires the extractor to be imported directly, so ensure they are available on the path
        full_path_extractors = os.path.abspath(path_extractors)
        full_path_above_extractors = os.path.dirname(full_path_extractors)
        # Modify the PATH so we can recognize this new package on import
        if full_path_extractors not in sys.path:
            sys.path.insert(1, full_path_extractors)
        if full_path_above_extractors not in sys.path:
            sys.path.insert(1, full_path_above_extractors)

        path_extractors = os.path.realpath(path_extractors)
        self.path: str = path_extractors
        self.extractors: Dict[str, ExtractorRegistration] = {}

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
                        metadata={
                            "family": member.family,
                            "author": member.author,
                            "last_modified": member.last_modified,
                            "sharing": member.sharing,
                            "description": member.__doc__,
                        },
                    )
                    namespaced_rules[name] = member.yara_rule or extractor.DEFAULT_YARA_RULE.format(name=name)

            # multiprocess logging is awkward - set up a queue to ensure we can log
            logging_queue = Queue()
            queue_handler = logging.handlers.QueueListener(logging_queue, *logging.getLogger().handlers)
            queue_handler.start()

            # Find the extractors within the given directory
            # Execute within a child process to ensure main process interpreter is kept clean
            p = Process(
                target=utils.proxy_logging,
                args=(
                    logging_queue,
                    utils.import_extractors,
                    extractor_module_callback,
                ),
                kwargs=dict(
                    root_directory=path_extractors,
                    scanner=yara.compile(source=utils.MACO_YARA_RULE),
                    create_venv=create_venv and os.path.isdir(path_extractors),
                    skip_install=skip_install,
                ),
            )
            p.start()
            p.join()

            # stop multiprocess logging
            queue_handler.stop()
            logging_queue.close()

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
        extractor_name: str,
    ) -> Dict[str, Any]:
        """Run extractor with stream and verify output matches the model.

        Args:
            stream (BinaryIO): Binary stream to analyze
            extractor_name (str): Name of extractor to analyze stream

        Returns:
            (Dict[str, Any]): Results from extractor
        """
        extractor = self.extractors[extractor_name]
        try:
            # Run extractor on a copy of the sample
            with NamedTemporaryFile() as sample_path:
                sample_path.write(stream.read())
                sample_path.flush()
                # enforce types and verify properties, and remove defaults
                return _verify_response(
                    utils.run_extractor(
                        sample_path.name,
                        module_name=extractor["module_name"],
                        extractor_class=extractor["extractor_class"],
                        module_path=extractor["module_path"],
                        venv=extractor["venv"],
                    )
                )
        except AnalysisAbortedException:
            # Extractor voluntarily aborted analysis of sample
            return
        except Exception:
            # caller can deal with the exception
            raise
        finally:
            # make sure to reset where we are in the file
            # otherwise follow on extractors are going to read 0 bytes
            stream.seek(0)
