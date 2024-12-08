import os

from maco import base_test

from demo_extractors.complex import complex_utils

class TestLimitOther(base_test.BaseTest):
    name = "LimitOther"
    path = os.path.join(__file__, "../../demo_extractors")

    def test_load_cart(self):
        data = self.load_cart("data/example.txt.cart").read()
        self.assertEqual(data, b"LimitOther\n")

    def test_subfunction(self):
        self.assertEqual(complex_utils.getdata(), {"result": 5})

    def test_run(self):
        ret = self.extract(self.load_cart("data/example.txt.cart"))
        self.assertEqual(ret["family"], "specify_other")
        self.assertEqual(ret["campaign_id"], ["12345"])
