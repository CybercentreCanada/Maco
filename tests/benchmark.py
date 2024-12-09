import cProfile
import io
import os
import timeit

from demo_extractors.complex import complex, complex_utils
from maco import base_test

instance = complex.Complex()

class TestComplex(base_test.BaseTest):
    name = "Complex"
    path = os.path.join(__file__, "../../demo_extractors")


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

def make():
    tc = TestComplex()
    tc.setUp()
    return tc


if __name__ == "__main__":
    print("maco hot loading and venv isolation")
    print(timeit.timeit("tc.test_auto_extract()", setup="from __main__ import make; tc=make()", number=100))
    print("bypass hack")
    print(timeit.timeit("tc.test_manual_extract()", setup="from __main__ import make; tc=make()", number=100))
