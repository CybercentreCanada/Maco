"""Test demo extractors."""

import os
import unittest

from maco import cli
from maco.collector import Collector


class TestDemoExtractors(unittest.TestCase):
    """Test demo extractors."""

    def test_complex(self):
        """Test complex extractor."""
        path_file = os.path.normpath(os.path.join(__file__, "../data/trigger_complex.txt"))
        collector = Collector(os.path.join(__file__, "../../demo_extractors"))
        self.assertEqual(
            set(collector.extractors.keys()),
            {"Elfy", "Nothing", "Complex", "LimitOther", "Terminator"},
        )

        with open(path_file, "rb") as stream:
            ret = cli.process_file(
                collector,
                path_file,
                stream,
                pretty=True,
                force=False,
                include_base64=False,
            )
        self.assertEqual(
            ret,
            {
                "Complex": {
                    "family": "complex",
                    "version": "5",
                    "decoded_strings": sorted(["Paradise", "Complex"]),
                    "binaries": [
                        {
                            "datatype": "payload",
                            "encryption": {"algorithm": "something"},
                            "sha256": "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee",
                            "size": 9,
                            "hex_sample": "736F6D652064617461",
                        }
                    ],
                    "http": [
                        {
                            "protocol": "https",
                            "hostname": "blarg5.com",
                            "path": "/malz/64",
                            "usage": "c2",
                        }
                    ],
                    "encryption": [{"algorithm": "sha256"}],
                }
            },
        )
