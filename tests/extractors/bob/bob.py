from io import BytesIO
from typing import List, Optional

import yara

from maco import extractor, model


class Bob(extractor.Extractor):
    """A simplistic script for testing."""

    family = "bob"
    author = "bob"
    last_modified = "2022-06-14"
