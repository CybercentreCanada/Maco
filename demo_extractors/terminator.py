from io import BytesIO
from typing import List, Optional

from maco import extractor, model, yara
from maco.exceptions import AnalysisAbortedException


class Terminator(extractor.Extractor):
    """Terminates early during extraction"""

    family = "terminator"
    author = "skynet"
    last_modified = "1997-08-29"

    def run(self, stream: BytesIO, matches: List[yara.Match]) -> Optional[model.ExtractorModel]:
        # Terminate early and indicate I can't run on this sample
        raise AnalysisAbortedException("I can't run on this sample")
