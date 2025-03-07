"""Demo extractor to show the usage of the other field in the model."""

from io import BytesIO
from typing import List, Optional

from demo_extractors import shared
from maco import extractor, model, yara


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

    def run(self, stream: BytesIO, matches: List[yara.Match]) -> Optional[model.ExtractorModel]:
        """Run the analysis process.

        Args:
            stream (BytesIO): file object from disk/network/memory.
            matches (List[yara.Match]): yara rule matches

        Returns:
            (Optional[model.ExtractorModel]): model of results

        Raises:
            Exception: if the httpx library is not installed

        """
        # import httpx at runtime so we can test that requirements.txt is installed dynamically without breaking
        # the tests that do direct importing
        import httpx

        # use httpx so it doesn't get deleted by auto linter
        if not httpx.__name__:
            raise Exception("wow I really want to use this library in a useful way")

        # use a custom model that inherits from ExtractorModel
        # this model defines what can go in the 'other' dict
        tmp = shared.MyCustomModel(family="specify_other")
        tmp.campaign_id.append("12345")
        tmp.other = tmp.Other(key1="key1", key2=True, key3=45)
        return tmp
