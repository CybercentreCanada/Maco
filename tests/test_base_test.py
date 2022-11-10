import io
import os

from maco import base_test


class TestExample(base_test.BaseTest):
    name = "LimitOther"
    path = os.path.join(__file__, "../../demo_extractors")
    data_path = os.path.join(os.path.dirname(__file__), "data")

    def test_load_cart(self):
        data = self.load_cart(os.path.join(self.data_path, "example.txt.cart")).read()
        self.assertEqual(data, b"LimitOther\n")

    def test_run(self):
        ret = self.extract(
            self.load_cart(os.path.join(self.data_path, "example.txt.cart"))
        )
        self.assertEqual(ret["family"], "specify_other")
