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

from ..common_neon.evm_config import EVMConfig
from ..common_neon.config import Config

from ..neon_core_api.neon_client import NeonClient

evm_config_data = NeonClient(Config()).get_evm_config()
EVMConfig().set_evm_config(evm_config_data)
