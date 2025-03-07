"""Benchmarking tests."""

import os
import timeit

from demo_extractors.complex import complex
from maco import base_test

# instance of extractor for synthetic comparison to maco
instance = complex.Complex()


class LocalBaseTest(base_test.BaseTest):
    """Local base test."""

    name = "Complex"
    path = os.path.join(__file__, "../../demo_extractors")
    create_venv = False

    @classmethod
    def setUpClass(cls) -> None:
        """Setup class."""
        super().setUpClass()
        cls.input_file = cls.load_cart("data/trigger_complex.txt.cart")
        cls.input_file.seek(0)


class TestComplexSynthetic(LocalBaseTest):
    """Test extractors work bypassing maco."""

    def test_extract(self):
        """Test extraction."""
        self.input_file.seek(0)
        raw = self.input_file.read()
        self.input_file.seek(0)
        # run yara rules against sample
        matches = instance.yara_compiled.match(data=raw)
        self.assertEqual(len(matches), 2)
        result = instance.run(self.input_file, [])
        self.assertEqual(result.family, "complex")


class TestComplexNoVenv(LocalBaseTest):
    """Test extractors work without full venv isolation."""

    def test_extract(self):
        """Test extraction without a virtual environment."""
        self.input_file.seek(0)
        ret = self.extract(self.input_file)
        self.assertEqual(ret["family"], "complex")
        self.assertEqual(ret["version"], "5")


class TestComplexVenv(LocalBaseTest):
    """Test extractors work when run with virtual environments."""

    create_venv = True

    def test_extract(self):
        """Test extraction with a virtual environment."""
        self.input_file.seek(0)
        ret = self.extract(self.input_file)
        self.assertEqual(ret["family"], "complex")
        self.assertEqual(ret["version"], "5")


def make_synthetic():
    """Make synthetic test.

    Returns:
        SyntheticTest
    """
    TestComplexSynthetic.setUpClass()
    tc = TestComplexSynthetic()
    tc.setUp()
    return tc


def make_no_venv():
    """Make no venv test.

    Returns:
        Test without virtual environment isolation
    """
    TestComplexNoVenv.setUpClass()
    tc = TestComplexNoVenv()
    tc.setUp()
    return tc


def make_venv():
    """Make venv test.

    Returns:
        Test with virtual environment isolation
    """
    TestComplexVenv.setUpClass()
    tc = TestComplexVenv()
    tc.setUp()
    return tc


if __name__ == "__main__":
    trials = 1000
    print(f"num trials: {trials}")
    print("results are number of seconds to execute total number of trials")
    print("synthetic comparison (directly import and execute extractor)")
    print(
        timeit.timeit(
            "tc.test_extract()",
            setup="from __main__ import make_synthetic; tc=make_synthetic()",
            number=trials,
        )
    )
    print("maco no venv isolation")
    print(
        timeit.timeit(
            "tc.test_extract()",
            setup="from __main__ import make_no_venv; tc=make_no_venv()",
            number=trials,
        )
    )
    print("maco venv isolation")
    print(
        timeit.timeit(
            "tc.test_extract()",
            setup="from __main__ import make_venv; tc=make_venv()",
            number=trials,
        )
    )
