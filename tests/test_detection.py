import pytest

from maco.collector import Collector


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
    ],
    ids=("jeFF0Falltrades/rat_king_parser", "apophis133/apophis-YARA-Rules"),
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
            project_name = repository_url.rsplit("/", 1)[1]
            Repo.clone_from(repository_url, os.path.join(working_dir, project_name), depth=1)

            collector = Collector(os.path.join(working_dir, extractor_path), create_venv=True)
            assert set(extractors) == set(collector.extractors.keys())
    else:
        pytest.skip("Unsupported Python version")


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


def test_CAPEv2():
    # Ensure that any changes we make doesn't break usage of public projects
    # which can affect downstream systems using like library (ie. Assemblyline)
    import os
    import sys
    import shutil

    from git import Repo
    from tempfile import TemporaryDirectory

    # TODO: Update this respective of https://github.com/kevoreilly/CAPEv2/pull/2373
    main_repository = "https://github.com/cccs-rs/CAPEv2"
    community_repository = "https://github.com/CAPESandbox/community"
    if sys.version_info >= (3, 10):
        with TemporaryDirectory() as working_dir:
            main_folder = os.path.join(working_dir, "CAPEv2")
            community_folder = os.path.join(working_dir, "community")

            # Merge community extensions with main project
            Repo.clone_from(main_repository, main_folder, depth=1, branch="extractor/to_MACO")
            Repo.clone_from(community_repository, community_folder, depth=1)
            shutil.copytree(community_folder, main_folder, dirs_exist_ok=True)

            collector = Collector(main_folder, create_venv=True)
            assert set(CAPE_EXTRACTORS) == set(collector.extractors.keys())
    else:
        pytest.skip("Unsupported Python version")
