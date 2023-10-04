# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import sys
import logging

logging.basicConfig(handlers=[logging.StreamHandler(sys.stdout)], level=logging.WARNING)

from solcx import install_solc
install_solc(version='0.7.6')

from ..common_neon.elf_params import ElfParams
from ..common_neon.config import Config

from ..neon_core_api.neon_cli import NeonCli

last_deployed_slot, elf_param_dict = NeonCli(Config(), False).read_elf_params(0)
ElfParams().set_elf_param_dict(elf_param_dict, last_deployed_slot)
