"""Example extractor that terminates early during extraction."""

from __future__ import annotations

from io import BytesIO

from maco import extractor, model, yara
from maco.exceptions import AnalysisAbortedException


class Terminator(extractor.Extractor):
    """Terminates early during extraction."""

    family = "terminator"
    author = "skynet"
    last_modified = "1997-08-29"

    def run(self, stream: BytesIO, matches: list[yara.Match]) -> model.ExtractorModel | None:
        """Run the analysis process but terminate early.

        Args:
            stream (BytesIO): file object from disk/network/memory.
            matches (list[yara.Match]): yara rule matches

        Raises:
            AnalysisAbortedException: Extractor has decided to terminate early
        """
        # Terminate early and indicate I can't run on this sample
        raise AnalysisAbortedException("I can't run on this sample")
