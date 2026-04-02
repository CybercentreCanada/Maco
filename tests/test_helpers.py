"""Test helper functions."""

import io
import os
import unittest

import pytest

from maco import collector

path_extractors = "../../demo_extractors"


class TestHelpersFindExtractors(unittest.TestCase):
    """Test finding extractors."""

    def test_find_extractors(self):
        """Test finding extractors."""
        target = os.path.join(__file__, path_extractors)
        m = collector.Collector(target)
        # extractors = helpers.find_extractors(target)
        self.assertEqual(len(m.extractors), 4)
        self.assertEqual(
            {x for x in m.extractors},
            {"Complex", "Elfy", "LimitOther", "Nothing"},
        )


class TestHelpersCompileYara(unittest.TestCase):
    """Test YARA rule compilation."""

    def test_compile_yara(self):
        """Test YARA rule compilation."""
        target = os.path.join(__file__, path_extractors)
        m = collector.Collector(target)
        self.assertEqual(
            {x.identifier for x in m.rules},
            {
                "Elfy",
                "Complex",
                "ComplexSubtext",
                "Nothing",
                "ComplexAlt",
                "LimitOther",
                "Terminator",
                "casing",
                "slow",
                "loopy",
                "cannot_count",
                "glob",
                "more_glob",
                "so_true",
                "bools",
                "aaa",
                "real_good_rule",
                "hex_is_hard",
            },
        )


class TestHelpersAnalyseStream(unittest.TestCase):
    """Test analyzing a stream."""

    def setUp(self):
        """Setup."""
        target = os.path.join(__file__, path_extractors)
        self.m = collector.Collector(target)

    def test_analyse_stream(self):
        """Test analyzing a stream."""
        data = b""
        resp = self.m.extract(io.BytesIO(data), "Complex")
        self.assertEqual(resp, None)

        data = b"data"
        resp = self.m.extract(io.BytesIO(data), "Complex")
        self.assertEqual(
            resp,
            {
                "family": "complex",
                "version": "5",
                "binaries": [
                    {
                        "datatype": "payload",
                        "data": b"some data",
                        "encryption": {"algorithm": "something"},
                    }
                ],
                "http": [
                    {
                        "protocol": "https",
                        "hostname": "blarg5.com",
                        "path": "/malz/4",
                        "usage": "c2",
                    }
                ],
                "encryption": [{"algorithm": "sha256"}],
            },
        )


@pytest.mark.parametrize(
    "data, expected",
    [
        (
            "schtasks /query /s REMOTE-PC01 /u DOMAIN\\AdminUser /p P@ssw0rd123 /fo csv /nh /v1",
            {
                "raw_command": "schtasks /query /s REMOTE-PC01 /u DOMAIN\\AdminUser /p P@ssw0rd123 /fo csv /nh /v1",
                "task_type": "QUERY",
                "remote_computer": "REMOTE-PC01",
                "user_domain": "DOMAIN",
                "user_account": "AdminUser",
                "user_password": "P@ssw0rd123",
                "kill": False,
                "interactive": False,
                "no_password": False,
                "auto_delete": False,
                "v1": True,
                "force": False,
                "output_format": "CSV",
                "no_header": True,
                "add_advanced_properties": False,
            },
        ),
        (
            'C:\\System32\\schtasks.exe /ruN /tn "DeleteWorker"',
            {
                "raw_command": 'C:\\System32\\schtasks.exe /ruN /tn "DeleteWorker"',
                "task_type": "RUN",
                "task_name": "DeleteWorker",
                "kill": False,
                "interactive": False,
                "no_password": False,
                "auto_delete": False,
                "v1": False,
                "force": False,
                "no_header": False,
                "add_advanced_properties": False,
            },
        ),
        (
            '\\System32\\schtasks.exe /Create /SC MINUTE /MO 13 /TN "LogoffWorker" /TR',
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
        ),
        (
            'schtasks /create /tn "MyRemoteTask2" /tr "C:\\Scripts\\new\\rackup.cmd" '
            "/sc ONEVENT /st 02:00 /s REMOTE-PC01 /u DOMAIN\\AdminUser /p AdminPassword123 "
            '/ru SYSTEM /rp "" /mo 5 /et 04:00 /du 2:00 /sd 01/01/2024 /ed 12/31/2024 '
            "/hresult 0x1 /v1 /f /rl HIGHEST /delay 00:05:00 /ri 51940 /i 214 /m JAN,MAR,JUL /d 1,15 "
            '/delay 00:05:00 /ec "System"',
            {
                "raw_command": 'schtasks /create /tn "MyRemoteTask2" /tr "C:\\Scripts\\new\\rackup.cmd" '
                '/sc ONEVENT /st 02:00 /s REMOTE-PC01 /u DOMAIN\\AdminUser /p AdminPassword123 /ru SYSTEM /rp "" '
                "/mo 5 /et 04:00 /du 2:00 /sd 01/01/2024 /ed 12/31/2024 /hresult 0x1 /v1 /f /rl HIGHEST "
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
        ),
    ],
)
def test_scheduled_task_parsing(data, expected):
    """Test scheduled task parsing."""
    from maco.model.helpers import parse_scheduled_task_command

    assert parse_scheduled_task_command(data).model_dump(exclude_none=True) == expected
