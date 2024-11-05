import os
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
    "repository_url, extractors, python_minor, branch",
    [
        ("https://github.com/jeFF0Falltrades/rat_king_parser", ["RKPMACO"], 10, None),
        (
            "https://github.com/apophis133/apophis-YARA-Rules",
            [
                "Pikabot",
                "TrueBot",
                "MetaStealer",
            ],
            8,
            None,
        ),
        # Pending: https://github.com/CAPESandbox/community/pull/470
        ("https://github.com/cccs-rs/community", CAPE_EXTRACTORS, 10, None),
    ],
    ids=("jeFF0Falltrades/rat_king_parser", "apophis133/apophis-YARA-Rules", "CAPESandbox/community"),
)
def test_public_projects(repository_url: str, extractors: list, python_minor: int, branch: str):
    # Ensure that any changes we make doesn't break usage of public projects
    # which can affect downstream systems using like library (ie. Assemblyline)
    import sys

    # Remove the tests directory from PATH to ensure the local 'git' directory doesn't conflict
    sys.path.pop(0)
    sys.modules.pop("git", None)

    from git import Repo
    from tempfile import TemporaryDirectory

    if sys.version_info >= (3, python_minor):
        with TemporaryDirectory() as working_dir:
            project_name = repository_url.rsplit("/", 1)[1]
            extractor_dir = os.path.join(working_dir, project_name)
            Repo.clone_from(repository_url, extractor_dir, depth=1, branch=branch)

            collector = Collector(extractor_dir, create_venv=True)
            assert set(extractors) == set(collector.extractors.keys())

            # Cleanup cached modules to not interfere with later tests
            for module in list(sys.modules.keys()):
                if module not in INIT_MODULES:
                    del sys.modules[module]
    else:
        pytest.skip("Unsupported Python version")


def test_module_confusion():
    # Directories that have the same name as the Python module, shouldn't cause confusion on loading the right module
    collector = Collector(os.path.join(__file__, "../extractors/bob"))
    assert collector.extractors["Bob"]

    collector = Collector(os.path.join(__file__, "../extractors"))
    assert collector.extractors["Bob"]

    # Existing packages shouldn't interfere with loading extractors from directories with similar names

    # Import the actual git package and not the local directory for this test
    sys.path.pop(0)
    sys.modules.pop("git", None)
    import git

    assert hasattr(git, "GIT_OK")

    collector = Collector(os.path.join(__file__, "../git"))

    # Ensure the extractor was collected and the path to the module exists (shouldn't be referenced to symlink anymore)
    assert collector.extractors["Bob"] and os.path.exists(collector.extractors["Bob"]["module_path"])
