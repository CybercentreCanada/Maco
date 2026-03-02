"""Demo extractor that returns nothing."""

from __future__ import annotations

from io import BytesIO

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

    def run(self, stream: BytesIO, matches: list[yara.Match]):
        """Run the analysis process.

        Args:
            stream (BytesIO): file object from disk/network/memory.
            matches (list[yara.Match]): yara rule matches
        """
        # return config model formatted results
        return
