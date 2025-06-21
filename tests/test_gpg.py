#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Gonzalo Alvarez

import pytest
from pathlib import Path
# from typing import List, Optional # No longer needed for this file

from secureenclave.gpg import Gpg
# from secureenclave.datamodel import GpgKey, GpgSubkey # No longer needed for this file


# Helper functions create_subkey and create_key have been moved to test_key_parser.py
# All test_dedup_keys_* functions have been moved to test_key_parser.py
# The gpg_instance fixture is removed as it's no longer used by any tests in this file.

# This file can be used for tests specific to the Gpg class methods,
# excluding _dedup_keys and _parse_gpg_list_cmd which are now in key_parser.py.

# Example of a test that might remain or be added here:
# @pytest.fixture
# def gpg_instance_for_gpg_tests():
#     # Setup a Gpg instance, possibly with a temporary gpg home
#     temp_home = Path("/tmp/test_gpg_home")
#     temp_home.mkdir(parents=True, exist_ok=True)
#     gpg = Gpg(homepath=temp_home)
#     # any other setup for gpg instance
#     yield gpg
#     # teardown, e.g., removing temp_home
#     import shutil
#     shutil.rmtree(temp_home, ignore_errors=True)

# def test_gpg_initialization(gpg_instance_for_gpg_tests):
#     assert gpg_instance_for_gpg_tests.gethome().exists()
#     assert gpg_instance_for_gpg_tests.gethome().joinpath("gpg.conf").exists()
