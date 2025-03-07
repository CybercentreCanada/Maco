"""Base testing."""

import io
import os

from demo_extractors.complex import complex, complex_utils
from maco import base_test


class TestLimitOther(base_test.BaseTest):
    """Test that limit_other extractor can be used in base environment."""

    name = "LimitOther"
    path = os.path.join(__file__, "../../demo_extractors")

    def test_load_cart(self):
        """Test loading a cart file."""
        data = self.load_cart("data/example.txt.cart").read()
        self.assertEqual(data, b"LimitOther\n")

    def test_extract(self):
        """Tests that we can run an extractor through maco."""
        ret = self.extract(self.load_cart("data/example.txt.cart"))
        self.assertEqual(ret["family"], "specify_other")
        self.assertEqual(ret["campaign_id"], ["12345"])


class TestComplex(base_test.BaseTest):
    """Test that complex extractor can be used in base environment."""

    name = "Complex"
    path = os.path.join(__file__, "../../demo_extractors")
    create_venv = False

    def test_extract(self):
        """Tests that we can run an extractor through maco."""
        ret = self.extract(self.load_cart("data/trigger_complex.txt.cart"))
        self.assertEqual(ret["family"], "complex")
        self.assertEqual(ret["version"], "5")

    def test_subfunction(self):
        """Tests that we can import directly from the extractor module and run a function."""
        self.assertEqual(complex_utils.getdata(), {"result": 5})

    def test_manual_extract(self):
        """Tests that we can run an extractor through maco."""
        ref = complex.Complex
        self.assertGreater(len(ref.yara_rule), 100)
        instance = complex.Complex()
        self.assertGreater(len(instance.yara_rule), 100)

        data = io.BytesIO(b"my malwarez")
        result = instance.run(data, [])
        self.assertEqual(result.family, "complex")


class TestComplexVenv(base_test.BaseTest):
    """Test that complex extractor can be used in full venv isolation."""

    name = "Complex"
    path = os.path.join(__file__, "../../demo_extractors")
    create_venv = True

    def test_extract(self):
        """Tests that we can run an extractor through maco."""
        ret = self.extract(self.load_cart("data/trigger_complex.txt.cart"))
        self.assertEqual(ret["family"], "complex")
        self.assertEqual(ret["version"], "5")


class TestTerminator(base_test.BaseTest):
    """Test that terminator extractor can be used in base environment."""

    name = "Terminator"
    path = os.path.join(__file__, "../../demo_extractors")
    create_venv = False

    def test_extract(self):
        """Tests that we can run an extractor through maco."""
        ret = self.extract(self.load_cart("data/trigger_complex.txt.cart"))
        self.assertEqual(ret, None)


class TestTerminatorVenv(base_test.BaseTest):
    """Test that terminator extractor can be used in base environment."""

    name = "Terminator"
    path = os.path.join(__file__, "../../demo_extractors")
    create_venv = True

    def test_extract(self):
        """Tests that we can run an extractor through maco."""
        ret = self.extract(self.load_cart("data/trigger_complex.txt.cart"))
        self.assertEqual(ret, None)
