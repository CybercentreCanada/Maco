#!/usr/bin/env python3
"""Setup script."""

from setuptools import setup

setup(
    python_requires=">=3.8",
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    packages=['maco.model'],
    include_package_data=True,
    install_requires=[
        r.strip() for r in open("requirements.txt", "r") if not r.startswith("pydantic")
    ],
    name="maco-model",
    description="",
    author="",
    author_email="",
    classifiers=[]
)
