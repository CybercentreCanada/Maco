from io import BytesIO
from typing import Dict, List, Optional

import yara

from maco import extractor, model


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

    def run(
        self, stream: BytesIO, matches: List[yara.Match]
    ) -> Optional[model.ExtractorModel]:
        # return config model formatted results
        return
