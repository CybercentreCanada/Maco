#!/usr/bin/env python3
"""Setup script."""

from setuptools import find_packages, setup

setup(
    python_requires=">=3.8",
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    packages=find_packages(".", exclude=["test", "tests", "extractors"]),
    include_package_data=True,
    install_requires=[
        r.strip() for r in open("requirements.txt", "r") if not r.startswith("#")
    ],
    name="maco",
    description="",
    author="",
    author_email="",
    classifiers=[],
    entry_points={
        "console_scripts": [
            "maco = maco.cli:main",
        ],
    },
)
