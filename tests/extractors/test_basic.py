import io
import os

from maco import base_test


class TestBasicLonger(base_test.BaseTest):
    """Test that an extractor containing the name of another extractor works properly."""

    name = "BasicLonger"
    path = os.path.join(__file__, "..")

    def test_run(self):
        ret = self.extract(io.BytesIO(b"BasicLonger"))
        self.assertEqual(ret["family"], "basic_longer")


class TestBasic(base_test.BaseTest):
    """Test that an extractor containing the name of another extractor works properly."""

    name = "Basic"
    path = os.path.join(__file__, "..")

    def test_run(self):
        ret = self.extract(io.BytesIO(b"Basic"))
        self.assertEqual(ret["family"], "basic")
