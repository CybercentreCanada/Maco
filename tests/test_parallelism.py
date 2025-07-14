"""Test extractor loading and import rewriting when executed in parallel."""

import os

from maco.collector import Collector
import unittest


class TestParallelism(unittest.TestCase):
    """Test parallel loading of maco extractors.

    This test only makes sense when run in parallel -- running a single instance will not test the affected areas.
    pytest-xdist needs to be installed to run these tests in parallel, use the -n flag to specify how many processes.
    2 or 4 is a reasonable number for the four test cases here.
    python -m pytest tests/test_parallelism.py -n 2
    """

    # determine path to test extractor
    working_dir = os.path.join(os.path.dirname(__file__), "extractors/import_rewriting")
    assert os.path.isdir(working_dir)

    # this value may need to be increased to ensure the errors occur, depending on your test system
    repetitions = 5

    def test_parallelism_1(self):
        """Test for one pytest-xdist worker."""
        for _ in range(self.repetitions):
            collector = Collector(self.working_dir, create_venv=False)

            # if extractor isn't overwritten, extractor will load
            # otherwise this raises an ExtractorLoadError because the extractor file is empty
            self.assertListEqual(list(collector.extractors.keys()), ["Importer"])

    def test_parallelism_2(self):
        """Test for one pytest-xdist worker."""
        for _ in range(self.repetitions):
            collector = Collector(self.working_dir, create_venv=False)

            # if extractor isn't overwritten, extractor will load
            # otherwise this raises an ExtractorLoadError because the extractor file is empty
            self.assertListEqual(list(collector.extractors.keys()), ["Importer"])

    def test_parallelism_3(self):
        """Test for one pytest-xdist worker."""
        for _ in range(self.repetitions):
            collector = Collector(self.working_dir, create_venv=False)

            # if extractor isn't overwritten, extractor will load
            # otherwise this raises an ExtractorLoadError because the extractor file is empty
            self.assertListEqual(list(collector.extractors.keys()), ["Importer"])

    def test_parallelism_4(self):
        """Test for one pytest-xdist worker."""
        for _ in range(self.repetitions):
            collector = Collector(self.working_dir, create_venv=False)

            # if extractor isn't overwritten, extractor will load
            # otherwise this raises an ExtractorLoadError because the extractor file is empty
            self.assertListEqual(list(collector.extractors.keys()), ["Importer"])
