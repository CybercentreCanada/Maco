"""Test detection of extractors."""

import os
import sys

import pytest

from maco.collector import Collector

INIT_MODULES = list(sys.modules.keys())
TESTS_DIR = os.path.dirname(__file__)

SEKOIA_EXTRACTORS = [
    "ConnectBack",
    "Ddostf",
    "Gafgyt",
    "SNOWLIGHT",
    "TShVariant",
    "Kaiji",
    # Extractors requiring libmono
    "Njrat",
    "QuasarRAT",
    "XWorm",
    "XenoRAT",
]


@pytest.mark.parametrize(
    "repository_url, extractors, python_minor, branch",
    [
        ("https://github.com/jeFF0Falltrades/rat_king_parser", ["RKPMACO"], 10, None),
        ("https://github.com/SEKOIA-IO/Community", SEKOIA_EXTRACTORS, 10, None),
    ],
    ids=("jeFF0Falltrades/rat_king_parser", "SEKOIA-IO/Community"),
)
def test_public_projects(repository_url: str, extractors: list, python_minor: int, branch: str):
    """Test compatibility with public projects."""
    # Ensure that any changes we make doesn't break usage of public projects
    # which can affect downstream systems using like library (ie. Assemblyline)
    import sys
    from tempfile import TemporaryDirectory

    from git import Repo

    if sys.version_info >= (3, python_minor):
        with TemporaryDirectory() as working_dir:
            project_name = repository_url.rsplit("/", 1)[1]
            extractor_dir = os.path.join(working_dir, project_name)
            Repo.clone_from(repository_url, extractor_dir, depth=1, branch=branch)

            collector = Collector(extractor_dir, create_venv=True)
            assert set(extractors) == set(collector.extractors.keys())

    else:
        pytest.skip("Unsupported Python version")


def test_module_confusion():
    """Test module confusion."""
    import shutil
    from tempfile import TemporaryDirectory

    import git

    # ensure that the git import is kept
    assert git.__name__

    # Directories that have the same name as the Python module, shouldn't cause confusion on loading the right module
    collector = Collector(os.path.join(__file__, "../extractors/bob"))
    assert collector.extractors["Bob"]

    collector = Collector(os.path.join(__file__, "../extractors"))
    assert collector.extractors["Bob"]

    # Existing packages shouldn't interfere with loading extractors from directories with similar names
    with TemporaryDirectory() as ex_copy:
        copy_ex_dir = f"{ex_copy}/git"
        shutil.copytree(f"{TESTS_DIR}/extractors", copy_ex_dir, dirs_exist_ok=True)
        collector = Collector(copy_ex_dir)
        assert collector.extractors["Bob"] and os.path.exists(collector.extractors["Bob"]["module_path"])
