import os
import logging
from typing import Dict

from ..common.logger import Logger
from ..common_neon.address import NeonAddress
from ..common_neon.config import Config
from ..common.logger import Logger

from .airdropper import Airdropper,AirdropperTrxAnalyzer
from .portal_analyzer import PortalTrxAnalyzer


LOG = logging.getLogger(__name__)


class AirdropperApp:

    def __init__(self):
        Logger.setup()
        LOG.info("Airdropper application is starting ...")
        config = Config()
        faucet_url = os.environ['FAUCET_URL']
        wrapper_whitelist = os.environ['INDEXER_ERC20_WRAPPER_WHITELIST']
        if wrapper_whitelist != 'ANY':
            wrapper_whitelist = wrapper_whitelist.split(',')

        max_conf = float(os.environ.get('MAX_CONFIDENCE_INTERVAL', 0.02))

        LOG.info(f"""Construct Airdropper with params: {str(config)}
                  faucet_url: {faucet_url},
                  wrapper_whitelist: {wrapper_whitelist},
                  Max confidence interval: {max_conf}""")

        airdropper_analyzers : Dict[NeonAddress,AirdropperTrxAnalyzer]={}

        portal_bridge_contracts = os.environ.get('PORTAL_BRIDGE_CONTRACTS', None)
        portal_bridge_tokens_whitelist = os.environ.get('PORTAL_BRIDGE_TOKENS_WHITELIST', None)
        if (portal_bridge_contracts is None) != (portal_bridge_tokens_whitelist is None):
            raise Exception("Need to specify both PORTAL_BRIDGE_CONTRACTS & PORTAL_BRIDGE_TOKENS_WHITELIST environment variables")
        elif portal_bridge_contracts is not None:
            tokens_whitelist = set() if portal_bridge_tokens_whitelist == 'ANY' else set(portal_bridge_tokens_whitelist.split(','))
            portal_analyzer = PortalTrxAnalyzer(tokens_whitelist)
            for address in portal_bridge_contracts.split(','):
                airdropper_analyzers[NeonAddress(address)] = portal_analyzer

        self._airdropper = Airdropper(config, faucet_url, wrapper_whitelist, airdropper_analyzers, max_conf)

    def run(self) -> int:
        try:
            self._airdropper.run()
        except BaseException as exc:
            LOG.error('Failed to start Airdropper', exc_info=exc)
            return 1
        return 0
