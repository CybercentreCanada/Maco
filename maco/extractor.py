"""Base class for an extractor script."""

import logging
import textwrap
from typing import BinaryIO, List, Optional, Union

import yara

from . import model


class InvalidExtractor(ValueError):
    pass

DEFAULT_YARA_RULE = \
"""
rule {name}
{{
    condition:
        true
}}
"""

class Extractor:
    """Base class for an analysis extractor with common entrypoint and metadata.

    Override this docstring with a good description of your extractor.
    """

    family: Union[str, List[str]] = None  # family or families of malware that is detected by the extractor
    author: str = None  # author of the extractor (name@organisation)
    last_modified: str = None  # last modified date (YYYY-MM-DD)
    sharing: str = "TLP:WHITE"  # who can this be shared with?
    yara_rule: str = None  # yara rule that we filter inputs with
    reference: str = None  # link to malware report or other reference information
    logger: logging.Logger = None  # logger for use when debugging

    def __init__(self) -> None:
        self.name = name = type(self).__name__
        self.logger = logging.getLogger(f"maco.extractor.{name}")
        self.logger.debug(f"initialise '{name}'")
        if not self.family or not self.author or not self.last_modified:
            raise InvalidExtractor("must set family, author, last_modified")
        # if author does not set a yara rule, match on everything
        if not self.yara_rule:
            self.yara_rule = DEFAULT_YARA_RULE.format(name=name)
        # unindent the yara rule from triple quoted string
        # this is for friendly printing, yara handles the rule ok either way
        self.yara_rule = textwrap.dedent(self.yara_rule)
        # check yara rules conform to expected structure
        # we throw away these compiled rules as we need all rules in system compiled together
        try:
            rules = yara.compile(source=self.yara_rule)
        except yara.SyntaxError as e:
            raise InvalidExtractor(f"{self.name} - invalid yara rule") from e
        # need to track which plugin owns the rules
        self.yara_rule_names = [x.identifier for x in rules]
        if not len(list(rules)):
            raise InvalidExtractor(f"{name} must define at least one yara rule")
        for x in rules:
            if x.is_global:
                raise InvalidExtractor(f"{x.identifier} yara rule must not be global")

    def run(self, stream: BinaryIO, matches: List[yara.Match]) -> Optional[model.ExtractorModel]:
        """Run the analysis process and return dict matching.

        :param stream: file object from disk/network/memory.
        :param match: yara rule match information contains locations of strings.
        """
        raise NotImplementedError()
