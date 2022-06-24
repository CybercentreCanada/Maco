"""Convenience functions for discovering your extractors."""
import importlib
import inspect
import logging
import os
import pkgutil
import sys
from typing import Any, BinaryIO, Dict, List

import yara

from . import extractor, model


class ExtractorLoadError(Exception):
    pass


logger = logging.getLogger("maco.lib.helpers")


class Collector:
    def __init__(
        self,
        path_extractors: str,
        include: List[str] = None,
        exclude: List[str] = None,
    ):
        """Discover and load extractors from file system."""
        self.path = path_extractors
        self.include = include
        self.exclude = exclude

        self.extractors = self._find_extractors()

        # compile yara rules gathered from extractors
        rules_merged = "\n".join([x.yara_rule for x in self.extractors.values()])
        self.rules = yara.compile(source=rules_merged)

        # map rule names to extractors, since each extractor can have multiple rules
        self.rule_map = {}
        for k, v in self.extractors.items():
            self.rule_map.update({r: k for r in v.yara_rule_names})

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
        logger.debug(f"{path_parent=}")
        logger.debug(f"{foldername=}")
        logger.debug(f"{sys.path=}")
        mod = importlib.import_module(foldername)

        # walk packages in the extractors directory to find all extactors
        extractors = {}
        for _, module_name, ispkg in pkgutil.walk_packages(
            mod.__path__, mod.__name__ + "."
        ):
            if ispkg:
                # skip __init__.py
                continue
            if not module_name.endswith(filename):
                # if filename was specified, skip modules that don't have that name
                continue
            logger.debug(f"inspecting '{module_name}' for extractors")
            # raise an exception if one of the potential extractors can't be imported
            # note that excluding an extractor through include/exclude does not prevent it being imported
            module = importlib.import_module(module_name)

            # find extractors in the module
            for _, member in inspect.getmembers(module):
                if not inspect.isclass(member):
                    # not a class
                    continue
                if not issubclass(member, extractor.Extractor):
                    # not an extractor
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
                extractors[name] = member()
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
            resp = extractor.run(stream, matches)
        except Exception:
            # caller can deal with the exception
            raise
        finally:
            # make sure to reset where we are in the file
            # otherwise follow on extractors are going to read 0 bytes
            stream.seek(0)

        # enforce types and verify properties, and remove defaults
        if resp is not None:
            # check the response is valid for its own model
            # this is useful if a restriction on the 'other' dictionary is needed
            resp_model = type(resp)
            if resp_model != model.ExtractorModel:
                resp_model.parse_obj(resp.dict())
            # check the response is valid according to the ExtractorModel
            resp = model.ExtractorModel.parse_obj(resp.dict()).dict(
                exclude_defaults=True
            )
        return resp
