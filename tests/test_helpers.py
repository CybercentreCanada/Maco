"""Test helper functions."""

import io
import os
import unittest

from maco import collector

path_extractors = "../../demo_extractors"


class TestHelpersFindExtractors(unittest.TestCase):
    """Test finding extractors."""

    def test_find_extractors(self):
        """Test finding extractors."""
        target = os.path.join(__file__, path_extractors)
        m = collector.Collector(target)
        # extractors = helpers.find_extractors(target)
        self.assertEqual(len(m.extractors), 4)
        self.assertEqual(
            {x for x in m.extractors.keys()},
            {"Complex", "Elfy", "LimitOther", "Nothing"},
        )


class TestHelpersCompileYara(unittest.TestCase):
    """Test YARA rule compilation."""

    def test_compile_yara(self):
        """Test YARA rule compilation."""
        target = os.path.join(__file__, path_extractors)
        m = collector.Collector(target)
        self.assertEqual(
            {x.identifier for x in m.rules},
            {"Elfy", "Complex", "ComplexSubtext", "Nothing", "ComplexAlt", "LimitOther", "Terminator"},
        )


class TestHelpersAnalyseStream(unittest.TestCase):
    """Test analyzing a stream."""

    def setUp(self):
        """Setup."""
        target = os.path.join(__file__, path_extractors)
        self.m = collector.Collector(target)

    def test_analyse_stream(self):
        """Test analyzing a stream."""
        data = b""
        resp = self.m.extract(io.BytesIO(data), "Complex")
        self.assertEqual(resp, None)

        data = b"data"
        resp = self.m.extract(io.BytesIO(data), "Complex")
        self.assertEqual(
            resp,
            {
                "family": "complex",
                "version": "5",
                "binaries": [
                    {
                        "datatype": "payload",
                        "data": b"some data",
                        "encryption": {"algorithm": "something"},
                    }
                ],
                "http": [
                    {
                        "protocol": "https",
                        "hostname": "blarg5.com",
                        "path": "/malz/4",
                        "usage": "c2",
                    }
                ],
                "encryption": [{"algorithm": "sha256"}],
            },
        )
