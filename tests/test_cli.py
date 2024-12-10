import os
import unittest

from maco import cli


class TestCLI(unittest.TestCase):
    def test_process_filesystem(self):
        maco_path = os.path.abspath(os.path.join(__file__, "../../demo_extractors"))
        test_path = os.path.abspath(os.path.join(__file__, "../data"))
        results = cli.process_filesystem(
            maco_path,
            test_path,
            include=[],
            exclude=[],
            pretty=True,
            force=False,
            include_base64=False,
        )
        self.assertEqual(results, (3, 3, 3))
