from io import BytesIO
from typing import List, Optional

import yara

from maco import extractor, model


class BasicLonger(extractor.Extractor):
    """A simplistic script for testing."""

    family = "basic_longer"
    author = "blue"
    last_modified = "2022-06-14"
    yara_rule = """
        rule BasicLonger
        {
            strings:
                $self_trigger = "BasicLonger"

            condition:
                $self_trigger
        }
        """

    def run(self, stream: BytesIO, matches: List[yara.Match]) -> Optional[model.ExtractorModel]:
        # use a custom model that inherits from ExtractorModel
        # this model defines what can go in the 'other' dict
        tmp = model.ExtractorModel(family="basic_longer")
        tmp.campaign_id.append("12345")
        tmp.other = dict(key1="key1", key2=True, key3=45)
        return tmp
