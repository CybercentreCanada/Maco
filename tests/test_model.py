import unittest
from typing import Dict

from pydantic import ValidationError

from maco import model


class TestModel(unittest.TestCase):
    def test_model_invalid(self):
        # family not supplied
        self.assertRaises(ValidationError, model.ExtractorModel)

        ret = model.ExtractorModel(family="octopus")
        # invalid property
        self.assertRaises(ValueError, setattr, *(ret, "invalid", 12345))
        # invalid type
        ret.sleep_delay = "test"
        self.assertRaises(ValidationError, self.verify, ret.model_dump())

    def test_model_1(self):
        # object example
        tmp = model.ExtractorModel(family="scuba")
        tmp.campaign_id.append("5467")
        self.verify(tmp.model_dump(), exclude_defaults=False)

    def test_model_2(self):
        # dict example
        self.verify(
            {
                "family": "scuba",
                "version": "30-01-2023",
                "http": [
                    {
                        "protocol": "https",
                        "hostname": "blarg.com",
                        "path": "/malz",
                        "usage": "c2",
                    }
                ],
            }
        )

    def test_model_3(self):
        # dict example large
        self.maxDiff = None

        self.verify(
            {
                "family": "scuba",
                "version": "lotso_stuff",
                "binaries": [
                    {
                        "data": rb"\x10\x20\x30\x40",
                        "encryption": {"algorithm": "alxor", "usage": "binary"},
                        "other": {
                            "datatype": ["payload"],
                            "extension": [".invalid"],
                            "label": ["xor 0x04 at 0x2130-0x2134"],
                            "some_junk": [1, 2, 3, 4, 5, 6],
                        },
                    },
                    {
                        "data": rb"\x50\x60\x70\x80",
                        "encryption": [
                            {"algorithm": "alxor", "usage": "binary"},
                            {"algorithm": "RC4", "usage": "binary"},
                        ],
                        "other": {
                            "datatype": ["payload"],
                        },
                    },
                ],
                "ftp": [{"hostname": "somewhere", "usage": "c2"}],
                "smtp": [{"hostname": "here.com", "usage": "upload"}],
                "http": [
                    {
                        "protocol": "https",
                        "hostname": "blarg.com",
                        "path": "/malz",
                        "usage": "c2",
                    }
                ],
                "ssh": [{"hostname": "bad.malware", "usage": "download"}],
                "proxy": [{"hostname": "192.168.0.80", "usage": "tunnel"}],
                "dns": [{"ip": "123.21.21.21", "usage": "other"}],
                "tcp": [{"server_ip": "73.21.32.43", "usage": "c2"}],
                "udp": [{"server_ip": "73.21.32.43", "usage": "c2"}],
                "encryption": [{"algorithm": "alxor", "usage": "binary"}],
                "service": [
                    {
                        "name": "DeviceMonitorSvc",
                        "display_name": "DeviceMonitorSvc",
                        "description": "Device Monitor Service",
                    }
                ],
                "cryptocurrency": [
                    {
                        "coin": "APE",
                        "address": "689fdh658790d6dr987yth84iyth7er8gtrfohyt9",
                        "usage": "miner",
                    }
                ],
                "paths": [
                    {"path": "C:/Windows/system32", "usage": "install"},
                    {"path": "C:/user/USERNAME/xxxxx/xxxxx/", "usage": "logs"},
                    {"path": "\\here\\is\\some\\place", "usage": "install"},
                ],
                "registry": [
                    {
                        "key": "HKLM_LOCAL_USER/some/location/to/key",
                        "usage": "store_data",
                    },
                    {"key": "HKLM_LOCAL_USER/system/location", "usage": "read"},
                ],
                "campaign_id": ["32"],
                "identifier": ["uxuduxuduxuudux"],
                "decoded_strings": ["there", "are", "some", "strings"],
                "password": ["hunter2"],
                "mutex": ["YEAH"],
                "pipe": ["xiod"],
                "sleep_delay": 45000,
                "inject_exe": ["Teams.exe"],
                "other": {"misc_data": {"nested": 5}},
            }
        )

    def verify(self, config: Dict, exclude_defaults: bool = True) -> Dict:
        """Verify the returned data matches the schema."""
        model_dict = model.ExtractorModel.model_validate(config).model_dump(
            exclude_defaults=exclude_defaults
        )
        self.assertEqual(model_dict, config)
        return model_dict
