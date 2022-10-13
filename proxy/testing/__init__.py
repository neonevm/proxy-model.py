# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from solcx import install_solc
install_solc(version='0.7.6')

from ..common_neon.elf_params import ElfParams
from ..common_neon.config import Config
ElfParams().read_elf_param_dict_from_net(Config())
