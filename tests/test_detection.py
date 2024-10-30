import pytest
import sys

from maco.collector import Collector

INIT_MODULES = list(sys.modules.keys())

CAPE_EXTRACTORS = [
    "AgentTesla",
    "AsyncRAT",
    "AuroraStealer",
    "Azorult",
    "BackOffLoader",
    "BackOffPOS",
    "BitPaymer",
    "BlackDropper",
    "BlackNix",
    "Blister",
    "BruteRatel",
    "BuerLoader",
    "BumbleBee",
    "Carbanak",
    "ChChes",
    "CobaltStrikeBeacon",
    "CobaltStrikeStager",
    "DCRat",
    "DarkGate",
    "DoppelPaymer",
    "DridexLoader",
    "Emotet",
    "Enfal",
    "EvilGrab",
    "Fareit",
    "Formbook",
    "Greame",
    "GuLoader",
    "Hancitor",
    "HttpBrowser",
    "IcedID",
    "IcedIDLoader",
    "KoiLoader",
    "Latrodectus",
    "LokiBot",
    "Lumma",
    "NanoCore",
    "Nighthawk",
    "Njrat",
    "Oyster",
    "Pandora",
    "PhemedroneStealer",
    "PikaBot",
    "PlugX",
    "PoisonIvy",
    "Punisher",
    "QakBot",
    "QuasarRAT",
    "Quickbind",
    "RCSession",
    "REvil",
    "RedLeaf",
    "RedLine",
    "Remcos",
    "Retefe",
    "Rhadamanthys",
    "Rozena",
    "SmallNet",
    "SmokeLoader",
    "Socks5Systemz",
    "SparkRAT",
    "SquirrelWaffle",
    "Stealc",
    "Strrat",
    "TSCookie",
    "TrickBot",
    "UrsnifV3",
    "VenomRAT",
    "WarzoneRAT",
    "XWorm",
    "XenoRAT",
    "Zloader",
]


@pytest.mark.parametrize(
    "repository_url, extractor_path, extractors, python_minor",
    [
        (
            "https://github.com/jeFF0Falltrades/rat_king_parser",
            "rat_king_parser",
            ["RKPMACO"],
            10,
        ),
        (
            "https://github.com/apophis133/apophis-YARA-Rules",
            "apophis-YARA-Rules",
            [
                "Pikabot",
                "TrueBot",
                "MetaStealer",
            ],
            8,
        ),
        (
            "https://github.com/kevoreilly/CAPEv2",
            "CAPEv2",
            CAPE_EXTRACTORS,
            10,
        ),
    ],
    ids=("jeFF0Falltrades/rat_king_parser", "apophis133/apophis-YARA-Rules", "kevoreilly/CAPEv2"),
)
def test_public_projects(repository_url: str, extractor_path: str, extractors: list, python_minor: int):
    # Ensure that any changes we make doesn't break usage of public projects
    # which can affect downstream systems using like library (ie. Assemblyline)
    import os
    import sys

    from git import Repo
    from tempfile import TemporaryDirectory

    if sys.version_info >= (3, python_minor):
        with TemporaryDirectory() as working_dir:
            sys.modules = {module: sys.modules[module] for module in INIT_MODULES}
            project_name = repository_url.rsplit("/", 1)[1]
            Repo.clone_from(repository_url, os.path.join(working_dir, project_name), depth=1)

            collector = Collector(os.path.join(working_dir, extractor_path), create_venv=True)
            assert set(extractors) == set(collector.extractors.keys())
    else:
        pytest.skip("Unsupported Python version")
