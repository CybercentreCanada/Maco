"""Basic extractor."""

from io import BytesIO
from typing import List

from maco import extractor, model, yara


class Basic(extractor.Extractor):
    """A simplistic script for testing."""

    family = "basic"
    author = "blue"
    last_modified = "2022-06-14"
    yara_rule = """
        rule Basic
        {
            strings:
                $self_trigger = "Basic"

            condition:
                $self_trigger
        }
        """

    def run(self, stream: BytesIO, matches: List[yara.Match]) -> model.ExtractorModel:
        """Run the extractor.

        Returns:
            (model.ExtractorModel): Results from extractor

        """
        # use a custom model that inherits from ExtractorModel
        # this model defines what can go in the 'other' dict
        tmp = model.ExtractorModel(family="basic")
        tmp.campaign_id.append("12345")
        tmp.other = dict(key1="key1", key2=True, key3=45)
        return tmp
