"""Demo extractor that returns nothing."""

from io import BytesIO
from typing import List

from maco import extractor, yara


class Nothing(extractor.Extractor):
    """Returns no extracted data."""

    family = "nothing"
    author = "blue"
    last_modified = "2022-06-14"
    yara_rule = """
        rule Nothing
        {
            strings:
                $self_trigger = "Nothing"

            condition:
                $self_trigger
        }
        """

    def run(self, stream: BytesIO, matches: List[yara.Match]):
        """Run the analysis process.

        Args:
            stream (BytesIO): file object from disk/network/memory.
            matches (List[yara.Match]): yara rule matches
        """
        # return config model formatted results
        return
