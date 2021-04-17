# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: AGPL-3.0-only
#
# Copyright © 2021 siddharth <s@ricketyspace.net>
#

from setuptools import setup, find_packages
from codecs import open
from os import path

from acmens import __version__

here = path.abspath(path.dirname(__file__))
with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

config = {
    "name": "acmens",
    "version": __version__,
    "description": "A simple ACMEv2 client. Fork of acme-nosudo.",
    "long_description": long_description,
    "long_description_content_type": "text/markdown",
    "url": "https://github.com/r5d/acmens",
    "author": "siddharth",
    "author_email": "s@ricketyspace.net",
    "license": "GNU Affero General Public License v3",
    "classifiers": [
        "Development Status :: 2 - Pre-Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Operating System :: POSIX :: BSD",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    "keywords": "acme letsencrypt acmens",
    "py_modules": ["acmens"],
    "python_requires": ">=3",
    "entry_points": {"console_scripts": ["acmens = acmens:main"]},
}
setup(**config)
