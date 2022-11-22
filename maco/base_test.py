"""Foundation for unit testing an extractor.

Example:

from maco import base_test
class TestExample(base_test.BaseTest):
    name = "Example"
    path = os.path.join(__file__, "../../extractors")
    def test_run(self):
        data = b"data with Example information"
        ret = self.extract(io.BytesIO(data))
        self.assertEqual(ret["family"], "example")
"""

import importlib
import io
import os
import unittest

import cart

from maco import collector


class NoHitException(Exception):
    pass


class BaseTest(unittest.TestCase):
    name: str = None  # name of the extractor
    # folder and/or file where extractor is.
    # I recommend something like os.path.join(__file__, "../../extractors")
    # if your extractors are in a folder 'extractors' next to a folder of tests
    path: str = None

    def setUp(self) -> None:
        if not self.name or not self.path:
            raise Exception("name and path must be set")
        self.c = collector.Collector(self.path, include=[self.name])
        self.assertIn(self.name, self.c.extractors)
        self.assertEqual(len(self.c.extractors), 1)
        return super().setUp()

    def extract(self, stream):
        """Return results for running extractor over stream, including yara check."""
        runs = self.c.match(stream)
        if not runs:
            raise NoHitException("no yara rule hit")
        hits = runs[self.name]
        resp = self.c.extract(stream, hits, self.name)
        return resp

    def _get_location(self) -> str:
        """Return path to child class that implements this class."""
        # import child module
        module = type(self).__module__
        i = importlib.import_module(module)
        # get location to child module
        return i.__file__

    def load_cart(self, filepath: str) -> io.BytesIO:
        """Load and unneuter a test file (likely malware) into memory for processing."""
        # it is nice if we can load files relative to whatever is implementing base_test
        dirpath = os.path.split(self._get_location())[0]
        # either filepath is absolute, or should be loaded relative to child of base_test
        filepath = os.path.join(dirpath, filepath)
        if not os.path.isfile(filepath):
            raise FileNotFoundError(filepath)
        with open(filepath, "rb") as f:
            unpacked = io.BytesIO()
            # just bubble exceptions if it isn't cart
            cart.unpack_stream(f, unpacked)
        # seek to start of the unneutered stream
        unpacked.seek(0)
        return unpacked
