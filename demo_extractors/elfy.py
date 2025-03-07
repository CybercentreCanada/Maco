"""Demo extractor that targets ELF files."""

from io import BytesIO
from typing import List, Optional

from maco import extractor, model, yara


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

    def run(self, stream: BytesIO, matches: List[yara.Match]) -> Optional[model.ExtractorModel]:
        """Run the analysis process.

        Args:
            stream (BytesIO): file object from disk/network/memory.
            matches (List[yara.Match]): yara rule matches

        Returns:
            (Optional[model.ExtractorModel]): model of results

        """
        # return config model formatted results
        ret = model.ExtractorModel(family=self.family)
        # the list for campaign_id already exists and is empty, so we just add an item
        ret.campaign_id.append(str(len(stream.read())))
        return ret
