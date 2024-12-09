import cProfile
import io
import os
import timeit

from demo_extractors.complex import complex, complex_utils
from maco import base_test

instance = complex.Complex()

class TestComplex(base_test.BaseTest):
    """Test extractors work under default conditions."""
    name = "Complex"
    path = os.path.join(__file__, "../../demo_extractors")
    create_venv=False

    def test_auto_extract(self):
        """Tests that we can run an extractor through maco."""
        inputs = self.load_cart("data/trigger_complex.txt.cart")
        inputs.seek(0)
        ret = self.extract(inputs)
        self.assertEqual(ret["family"], "complex")
        self.assertEqual(ret["version"], "5")

    def test_manual_extract(self):
        """Tests that we can run an extractor through maco."""
        inputs = self.load_cart("data/trigger_complex.txt.cart")
        inputs.seek(0)
        result = instance.run(inputs, [])
        self.assertEqual(result.family, "complex")

class TestComplexVenv(base_test.BaseTest):
    """Test extractors work when run with virtual environments."""
    name = "Complex"
    path = os.path.join(__file__, "../../demo_extractors")
    create_venv=True

    def test_auto_extract(self):
        """Tests that we can run an extractor through maco."""
        inputs = self.load_cart("data/trigger_complex.txt.cart")
        inputs.seek(0)
        ret = self.extract(inputs)
        self.assertEqual(ret["family"], "complex")
        self.assertEqual(ret["version"], "5")

def make():
    tc = TestComplex()
    tc.setUp()
    return tc

def make_venv():
    tc = TestComplexVenv()
    tc.setUp()
    return tc


if __name__ == "__main__":
    print("bypass hack - synthetic comparison (directly import and execute extractor)")
    print(timeit.timeit("tc.test_manual_extract()", setup="from __main__ import make; tc=make()", number=1000))
    print("maco no venv isolation")
    print(timeit.timeit("tc.test_auto_extract()", setup="from __main__ import make; tc=make()", number=1000))
    print("maco venv isolation")
    print(timeit.timeit("tc.test_auto_extract()", setup="from __main__ import make; tc=make_venv()", number=1000))
