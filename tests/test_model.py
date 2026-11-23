"""Model validation testing."""

from __future__ import annotations

import unittest

from pydantic import ValidationError

from maco import collector, model
from maco.model.helpers import parse_scheduled_task_command


class TestModelObject(unittest.TestCase):
    """Test the model object."""

    maxDiff = None

    def test_model_invalid(self):
        """Test invalid model."""
        # family not supplied
        self.assertRaises(ValidationError, model.ExtractorModel)

        ret = model.ExtractorModel(family="octopus")
        # invalid property
        self.assertRaises(ValueError, setattr, *(ret, "invalid", 12345))
        # invalid type
        ret.sleep_delay = "test"
        self.assertRaises(ValidationError, collector._verify_response, ret)

    def test_model_object_1(self):
        """Test the model object with basic requirements."""
        # object example
        tmp = model.ExtractorModel(family="scuba")
        tmp.campaign_id.append("5467")
        self.verify(tmp, {"family": "scuba", "campaign_id": ["5467"]})

    def test_model_object_2(self):
        """Test the model object with more data."""
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
                        password=None,
                        salt=None,
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
                            password=None,
                            salt=None,
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
                            password=None,
                            salt=None,
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
            icmp=[
                em.ICMP(
                    type=None,
                    code=None,
                    header="DEADBEEF",
                    hostname="192.168.0.80",
                    usage="c2",
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
                    password=None,
                    salt=None,
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
            online_services=[
                em.OnlineService(
                    service_name="many buckets",
                    container="the_malware_bucket",
                    identifier="important_document.pdf.exe",
                    token="abc123",
                    api_key="d41d8cd98f00b204e9800998ecf8427e",
                    secret="SSSSHHHHHHH",
                    username="cletus",
                    password="hunter2",
                    region="us-east-1",
                    domain="www.example.com",
                    url="files.example.com/payload/?exploit=1&soup=tomato",
                    fragment="?malware=plz&fun=yes",
                    usage="download",
                ),
                em.OnlineService(
                    service_name="Steam", api_key="0754ac3ddc26ee4ccfde05f81a2eafac", usage="dead_drop_resolver"
                ),
                em.OnlineService(
                    service_name="VirusTotal",
                    api_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    identifier="exfil.zip",
                    usage="upload",
                ),
                em.OnlineService(
                    service_name="Pastebin", url="https://pastebin.com/raw/VbSn9AnN", identifier="VbSn9AnN", usage="c2"
                ),
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
                "icmp": [{"header": "DEADBEEF", "hostname": "192.168.0.80", "usage": "c2"}],
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
                "online_services": [
                    {
                        "service_name": "many buckets",
                        "container": "the_malware_bucket",
                        "identifier": "important_document.pdf.exe",
                        "token": "abc123",
                        "api_key": "d41d8cd98f00b204e9800998ecf8427e",
                        "secret": "SSSSHHHHHHH",
                        "username": "cletus",
                        "password": "hunter2",
                        "region": "us-east-1",
                        "domain": "www.example.com",
                        "url": "files.example.com/payload/?exploit=1&soup=tomato",
                        "fragment": "?malware=plz&fun=yes",
                        "usage": "download",
                    },
                    {
                        "service_name": "Steam",
                        "api_key": "0754ac3ddc26ee4ccfde05f81a2eafac",
                        "usage": "dead_drop_resolver",
                    },
                    {
                        "service_name": "VirusTotal",
                        "api_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "identifier": "exfil.zip",
                        "usage": "upload",
                    },
                    {
                        "service_name": "Pastebin",
                        "url": "https://pastebin.com/raw/VbSn9AnN",
                        "identifier": "VbSn9AnN",
                        "usage": "c2",
                    },
                ],
            },
        )

    def test_model_object_3(self):
        """Test the model object with more data."""
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
                        password=None,
                        salt=None,
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
                            password=None,
                            salt=None,
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
                            password=None,
                            salt=None,
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
            icmp=[
                em.ICMP(
                    type=None,
                    code=None,
                    header="DEADBEEF",
                    hostname="192.168.0.80",
                    usage="c2",
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
                    password=None,
                    salt=None,
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
            warnings=[
                em.Warning(message="random warning message"),
                em.Warning(message="random warning message with trace", stack_trace="Stack trace value!"),
            ],
            online_services=[
                em.OnlineService(
                    service_name="Azure",
                    api_key="abcd1234ef567890",
                    token="1234abcd567890ef",
                    secret="shhhhh",
                    usage="upload",
                ),
                em.OnlineService(
                    service_name="Dropbox",
                    api_key="1111111111111112",
                    secret="shhhh",
                    usage="download",
                    fragment="/s/aaaaaaa/not_malware.exe?dl=1",
                    domain="www.dropbox.com",
            scheduled_tasks=[
                parse_scheduled_task_command(
                    '\\System32\\schtasks.exe /Create /SC MINUTE /MO 13 /TN "LogoffWorker" /TR'
                ),
                parse_scheduled_task_command(
                    'schtasks /create /tn "MyRemoteTask2" /tr "C:\\Scripts\\new\\rackup.cmd" /sc ONEVENT /st 02:00 '
                    '/s REMOTE-PC01 /u DOMAIN\\AdminUser /p AdminPassword123 /ru SYSTEM /rp "" /mo 5 /et 04:00 /du '
                    "2:00 /sd 01/01/2024 /ed 12/31/2024 /hresult 0x1 /v1 /f /rl HIGHEST /delay 00:05:00 /ri 51940 "
                    '/i 214 /m JAN,MAR,JUL /d 1,15 /delay 00:05:00 /ec "System"'
                ),
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
                "http": [{"protocol": "https", "hostname": "blarg.com", "path": "/malz", "usage": "c2"}],
                "ssh": [{"hostname": "bad.malware", "usage": "download"}],
                "proxy": [{"hostname": "192.168.0.80", "usage": "tunnel"}],
                "icmp": [{"header": "DEADBEEF", "hostname": "192.168.0.80", "usage": "c2"}],
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
                    {"coin": "APE", "address": "689fdh658790d6dr987yth84iyth7er8gtrfohyt9", "usage": "miner"}
                ],
                "paths": [
                    {"path": "C:/Windows/system32", "usage": "install"},
                    {"path": "C:/user/USERNAME/xxxxx/xxxxx/", "usage": "logs"},
                    {"path": "\\here\\is\\some\\place", "usage": "install"},
                ],
                "registry": [
                    {"key": "HKLM_LOCAL_USER/some/location/to/key", "usage": "store_data"},
                    {"key": "HKLM_LOCAL_USER/system/location", "usage": "read"},
                ],
                "warnings": [
                    {"message": "random warning message"},
                    {"message": "random warning message with trace", "stack_trace": "Stack trace value!"},
                ],
                "online_services": [
                    {
                        "service_name": "Azure",
                        "api_key": "abcd1234ef567890",
                        "token": "1234abcd567890ef",
                        "secret": "shhhhh",
                        "usage": "upload",
                    },
                    {
                        "service_name": "Dropbox",
                        "api_key": "1111111111111112",
                        "secret": "shhhh",
                        "fragment": "/s/aaaaaaa/not_malware.exe?dl=1",
                        "domain": "www.dropbox.com",
                        "usage": "download",
                "scheduled_tasks": [
                    {
                        "raw_command": '\\System32\\schtasks.exe /Create /SC MINUTE /MO 13 /TN "LogoffWorker" /TR',
                        "task_type": "CREATE",
                        "schedule_type": "MINUTE",
                        "task_name": "LogoffWorker",
                        "task_run": "",
                        "modifier": "13",
                        "kill": False,
                        "interactive": False,
                        "no_password": False,
                        "auto_delete": False,
                        "v1": False,
                        "force": False,
                        "no_header": False,
                        "add_advanced_properties": False,
                    },
                    {
                        "raw_command": 'schtasks /create /tn "MyRemoteTask2" /tr "C:\\Scripts\\new\\rackup.cmd" '
                        "/sc ONEVENT /st 02:00 /s REMOTE-PC01 /u DOMAIN\\AdminUser /p AdminPassword123 /ru SYSTEM "
                        '/rp "" /mo 5 /et 04:00 /du 2:00 /sd 01/01/2024 /ed 12/31/2024 /hresult 0x1 /v1 /f /rl HIGHEST '
                        '/delay 00:05:00 /ri 51940 /i 214 /m JAN,MAR,JUL /d 1,15 /delay 00:05:00 /ec "System"',
                        "task_type": "CREATE",
                        "schedule_type": "ONEVENT",
                        "task_name": "MyRemoteTask2",
                        "task_run": "C:\\Scripts\\new\\rackup.cmd",
                        "remote_computer": "REMOTE-PC01",
                        "user_domain": "DOMAIN",
                        "user_account": "AdminUser",
                        "user_password": "AdminPassword123",
                        "run_as": "SYSTEM",
                        "run_as_password": '""',
                        "modifier": "5",
                        "day": "1,15",
                        "month": "JAN,MAR,JUL",
                        "idle_time": "214",
                        "start_time": "02:00",
                        "interval": "51940",
                        "end_time": "04:00",
                        "duration": "2:00",
                        "kill": False,
                        "start_date": "01/01/2024",
                        "end_date": "12/31/2024",
                        "channel_name": "System",
                        "interactive": False,
                        "no_password": False,
                        "auto_delete": False,
                        "v1": True,
                        "force": True,
                        "run_level": "HIGHEST",
                        "delay_time": "00:05:00",
                        "hresult": "0x1",
                        "no_header": False,
                        "add_advanced_properties": False,
                    },
                ],
            },
        )

    def verify(self, in1, in2: dict):
        """Verify the returned data matches the schema."""
        resp = collector._verify_response(in1)
        if resp:
            resp = resp.model_dump(exclude_defaults=True)
        self.assertEqual(resp, in2)


class TestModelDict(unittest.TestCase):
    """Test verifying dicts against the schema."""

    def test_model_1(self):
        """Test the model object with basic requirements."""
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
        """Test the model object with more data."""
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

    def test_model_with_warnings(self):
        """Test the model object with more data."""
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
                "warnings": [
                    {
                        "message": "warning has occurred",
                        "stack_trace": "silly stack trace here\nhopefully it helps you find the issue\n",
                    },
                    {
                        "message": "warning has occurred no trace",
                    },
                ],
            }
        )

    def verify(self, config: dict):
        """Verify the returned data matches the schema."""
        tmp = model.ExtractorModel.model_validate(config)
        resp = collector._verify_response(tmp)
        if resp:
            resp = resp.model_dump(exclude_defaults=True)
        self.assertEqual(resp, config)
