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
from maco.exceptions import NoHitException


class BaseTest(unittest.TestCase):
    """Base test class."""

    name: str = None  # name of the extractor
    # folder and/or file where extractor is.
    # I recommend something like os.path.join(__file__, "../../extractors")
    # if your extractors are in a folder 'extractors' next to a folder of tests
    path: str = None
    create_venv: bool = False

    @classmethod
    def setUpClass(cls) -> None:
        """Initialization of class.

        Raises:
            Exception: when name or path is not set.
        """
        if not cls.name or not cls.path:
            raise Exception("name and path must be set")
        cls.c = collector.Collector(cls.path, include=[cls.name], create_venv=cls.create_venv)
        return super().setUpClass()

    def test_default_metadata(self):
        """Require extractor to be loadable and valid."""
        self.assertIn(self.name, self.c.extractors)
        self.assertEqual(len(self.c.extractors), 1)

    def extract(self, stream):
        """Return results for running extractor over stream, including yara check.

        Raises:
            NoHitException: when yara rule doesn't hit.
        """
        runs = self.c.match(stream)
        if not runs:
            raise NoHitException("no yara rule hit")
        resp = self.c.extract(stream, self.name)
        return resp

    @classmethod
    def _get_location(cls) -> str:
        """Return path to child class that implements this class."""
        # import child module
        module = cls.__module__
        i = importlib.import_module(module)
        # get location to child module
        return i.__file__

    @classmethod
    def load_cart(cls, filepath: str) -> io.BytesIO:
        """Load and unneuter a test file (likely malware) into memory for processing.

        Args:
            filepath (str): Path to carted sample

        Returns:
            (io.BytesIO): Buffered stream containing the un-carted sample

        Raises:
            FileNotFoundError: if the path to the sample doesn't exist
        """
        # it is nice if we can load files relative to whatever is implementing base_test
        dirpath = os.path.split(cls._get_location())[0]
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
