import unittest

import yara

from maco import extractor


class TestExtractor(unittest.TestCase):
    def test_bad(self):
        class Tmp(extractor.Extractor):
            family = "smell_ya_later"
            author = "me"
            last_modified = "yeah"

        Tmp()

        class Tmp1(Tmp):
            family = None

        self.assertRaises(extractor.InvalidExtractor, Tmp1)

        class Tmp1(extractor.Extractor):
            author = None

        self.assertRaises(extractor.InvalidExtractor, Tmp1)

        class Tmp1(extractor.Extractor):
            version = None

        self.assertRaises(extractor.InvalidExtractor, Tmp1)

        class Tmp1(Tmp):
            yara_rule: str = "t"

        self.assertRaises(extractor.InvalidExtractor, Tmp1)

        class Tmp1(Tmp):
            yara_rule = """
                rule DifferentName
                {
                    condition:
                        true
                }
            """

        Tmp1()

        class Tmp1(Tmp):
            yara_rule = """
                rule Tmp1
                {
                    condition:
                        true
                }
                rule OtherName
                {
                    condition:
                        true
                }
            """

        Tmp1()
