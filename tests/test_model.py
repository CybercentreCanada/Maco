import unittest
from typing import Dict

from pydantic import ValidationError

from maco import collector, model


class TestModelObject(unittest.TestCase):
    maxDiff = None

    def test_model_invalid(self):
        # family not supplied
        self.assertRaises(ValidationError, model.ExtractorModel)

        ret = model.ExtractorModel(family="octopus")
        # invalid property
        self.assertRaises(ValueError, setattr, *(ret, "invalid", 12345))
        # invalid type
        ret.sleep_delay = "test"
        self.assertRaises(ValidationError, collector._verify_response, ret)

    def test_model_object_1(self):
        # object example
        tmp = model.ExtractorModel(family="scuba")
        tmp.campaign_id.append("5467")
        self.verify(tmp, {"family": "scuba", "campaign_id": ["5467"]})

    def test_model_object_2(self):
        em = model.ExtractorModel
        tmp = model.ExtractorModel(
            family="scuba",
            version="lotso_stuff",
            category=[],
            attack=[],
            capability_enabled=[],
            capability_disabled=[],
            campaign_id=["32"],
            identifier=["uxuduxuduxuudux"],
            decoded_strings=["there", "are", "some", "strings"],
            password=["hunter2"],
            mutex=["YEAH"],
            pipe=["xiod"],
            sleep_delay=45000,
            sleep_delay_jitter=2500,
            inject_exe=["Teams.exe"],
            other={"misc_data": {"nested": 5}},
            binaries=[
                em.Binary(
                    datatype=None,
                    data=b"\x10\x20\x30\x40",
                    other={
                        "datatype": ["payload"],
                        "extension": [".invalid"],
                        "label": ["xor 0x04 at 0x2130-0x2134"],
                        "some_junk": [1, 2, 3, 4, 5, 6],
                    },
                    encryption=em.Binary.Encryption(
                        algorithm="alxor",
                        public_key=None,
                        key=None,
                        provider=None,
                        mode=None,
                        iv=None,
                        seed=None,
                        nonce=None,
                        constants=[],
                        usage="binary",
                    ),
                ),
                em.Binary(
                    datatype=None,
                    data=b"\x50\x60\x70\x80",
                    other={"datatype": ["payload"]},
                    encryption=[
                        em.Binary.Encryption(
                            algorithm="alxor",
                            public_key=None,
                            key=None,
                            provider=None,
                            mode=None,
                            iv=None,
                            seed=None,
                            nonce=None,
                            constants=[],
                            usage="binary",
                        ),
                        em.Binary.Encryption(
                            algorithm="RC4",
                            public_key=None,
                            key=None,
                            provider=None,
                            mode=None,
                            iv=None,
                            seed=None,
                            nonce=None,
                            constants=[],
                            usage="binary",
                        ),
                    ],
                ),
            ],
            ftp=[
                em.FTP(
                    username=None,
                    password=None,
                    hostname="somewhere",
                    port=None,
                    path=None,
                    usage="c2",
                )
            ],
            smtp=[
                em.SMTP(
                    username=None,
                    password=None,
                    hostname="here.com",
                    port=None,
                    mail_to=[],
                    mail_from=None,
                    subject=None,
                    usage="upload",
                )
            ],
            http=[
                em.Http(
                    uri=None,
                    protocol="https",
                    username=None,
                    password=None,
                    hostname="blarg.com",
                    port=None,
                    path="/malz",
                    query=None,
                    fragment=None,
                    user_agent=None,
                    method=None,
                    headers=None,
                    max_size=None,
                    usage="c2",
                )
            ],
            ssh=[
                em.SSH(
                    username=None,
                    password=None,
                    hostname="bad.malware",
                    port=None,
                    usage="download",
                )
            ],
            proxy=[
                em.Proxy(
                    protocol=None,
                    username=None,
                    password=None,
                    hostname="192.168.0.80",
                    port=None,
                    usage="tunnel",
                )
            ],
            dns=[em.DNS(ip="123.21.21.21", port=None, usage="other")],
            tcp=[
                em.Connection(
                    client_ip=None,
                    client_port=None,
                    server_ip="73.21.32.43",
                    server_domain=None,
                    server_port=None,
                    usage="c2",
                )
            ],
            udp=[
                em.Connection(
                    client_ip=None,
                    client_port=None,
                    server_ip="73.21.32.43",
                    server_domain=None,
                    server_port=None,
                    usage="c2",
                )
            ],
            encryption=[
                em.Encryption(
                    algorithm="alxor",
                    public_key=None,
                    key=None,
                    provider=None,
                    mode=None,
                    iv=None,
                    seed=None,
                    nonce=None,
                    constants=[],
                    usage="binary",
                )
            ],
            service=[
                em.Service(
                    dll=None,
                    name="DeviceMonitorSvc",
                    display_name="DeviceMonitorSvc",
                    description="Device Monitor Service",
                )
            ],
            cryptocurrency=[
                em.Cryptocurrency(
                    coin="APE",
                    address="689fdh658790d6dr987yth84iyth7er8gtrfohyt9",
                    ransom_amount=None,
                    usage="miner",
                )
            ],
            paths=[
                em.Path(path="C:/Windows/system32", usage="install"),
                em.Path(path="C:/user/USERNAME/xxxxx/xxxxx/", usage="logs"),
                em.Path(path="\\here\\is\\some\\place", usage="install"),
            ],
            registry=[
                em.Registry(key="HKLM_LOCAL_USER/some/location/to/key", usage="store_data"),
                em.Registry(key="HKLM_LOCAL_USER/system/location", usage="read"),
            ],
        )
        self.verify(
            tmp,
            {
                "family": "scuba",
                "version": "lotso_stuff",
                "campaign_id": ["32"],
                "identifier": ["uxuduxuduxuudux"],
                "decoded_strings": ["there", "are", "some", "strings"],
                "password": ["hunter2"],
                "mutex": ["YEAH"],
                "pipe": ["xiod"],
                "sleep_delay": 45000,
                "sleep_delay_jitter": 2500,
                "inject_exe": ["Teams.exe"],
                "other": {"misc_data": {"nested": 5}},
                "binaries": [
                    {
                        "data": b"\x10 0@",
                        "other": {
                            "datatype": ["payload"],
                            "extension": [".invalid"],
                            "label": ["xor 0x04 at 0x2130-0x2134"],
                            "some_junk": [1, 2, 3, 4, 5, 6],
                        },
                        "encryption": {"algorithm": "alxor", "usage": "binary"},
                    },
                    {
                        "data": b"P`p\x80",
                        "other": {"datatype": ["payload"]},
                        "encryption": [
                            {"algorithm": "alxor", "usage": "binary"},
                            {"algorithm": "RC4", "usage": "binary"},
                        ],
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
            },
        )

    def verify(self, in1, in2: Dict) -> Dict:
        """Verify the returned data matches the schema."""
        resp = collector._verify_response(in1)
        self.assertEqual(resp, in2)


class TestModelDict(unittest.TestCase):
    def test_model_1(self):
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

    def test_model_2(self):
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

    def verify(self, config: Dict) -> Dict:
        """Verify the returned data matches the schema."""
        tmp = model.ExtractorModel.model_validate(config)
        resp = collector._verify_response(tmp)
        self.assertEqual(resp, config)
