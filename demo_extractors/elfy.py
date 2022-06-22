from io import BytesIO
from typing import Dict, List, Optional

import yara

from maco import extractor, model


class Elfy(extractor.Extractor):
    """Check basic elf property."""

    family = "elfy"
    author = "blue"
    last_modified = "2022-06-14"
    yara_rule = """
        import "elf"

        rule Elfy
        {
            condition:
                elf.number_of_sections > 50
        }
        """

    def run(
        self, stream: BytesIO, matches: List[yara.Match]
    ) -> Optional[model.ExtractorModel]:
        # return config model formatted results
        ret = model.ExtractorModel(family=self.family)
        # the list for campaign_id already exists and is empty, so we just add an item
        ret.campaign_id.append(str(len(stream.read())))
        return ret
