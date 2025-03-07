"""Simple extractor for testing module and submodule with the same name."""

from maco import extractor


class Bob(extractor.Extractor):
    """A simplistic script for testing."""

    family = "bob"
    author = "bob"
    last_modified = "2022-06-14"
