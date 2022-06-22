from io import BytesIO
from typing import Dict, List, Optional

import yara

from maco import extractor, model

from . import shared


class LimitOther(extractor.Extractor):
    """An example of how the 'other' dictionary can be limited in a custom way."""

    family = "limit_other"
    author = "blue"
    last_modified = "2022-06-14"
    yara_rule = """
        rule LimitOther
        {
            strings:
                $self_trigger = "LimitOther"

            condition:
                $self_trigger
        }
        """

    def run(
        self, stream: BytesIO, matches: List[yara.Match]
    ) -> Optional[model.ExtractorModel]:
        # use a custom model that inherits from ExtractorModel
        # this model defines what can go in the 'other' dict
        tmp = shared.MyCustomModel(family="specify_other")
        tmp.campaign_id.append("12345")
        tmp.other = tmp.Other(key1="key1", key2=True, key3=45)
        return tmp
