import os
import logging
from typing import Dict

from ..common.logger import Logger
from ..common_neon.address import NeonAddress
from ..common_neon.config import Config
from ..common.logger import Logger

from .airdropper import Airdropper,AirdropperTrxAnalyzer
from .portal_analyzer import PortalTrxAnalyzer
from .common_erc20_bridge_analyzer import CommonERC20BridgeAnalyzer


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
                neon_address = NeonAddress(address)
                if neon_address in airdropper_analyzers:
                    raise Exception(f'Address {neon_address} already specified to analyze')
                airdropper_analyzers[neon_address] = portal_analyzer

        erc20_bridge_contracts = os.environ.get('ERC20_BRIDGE_CONTRACTS', None)
        erc20_bridge_tokens_whitelist = os.environ.get('ERC20_BRIDGE_TOKENS_WHITELIST', None)
        if (erc20_bridge_contracts is None) != (erc20_bridge_tokens_whitelist is None):
            raise Exception("Need to specify both ERC20_BRIDGE_CONTRACTS & ERC20_BRIDGE_TOKENS_WHITELIST environment variables")
        elif erc20_bridge_contracts is not None:
            tokens_whitelist = set() if erc20_bridge_tokens_whitelist == 'ANY' else set(erc20_bridge_tokens_whitelist.split(','))
            erc20_bridge_analyzer = CommonERC20BridgeAnalyzer(tokens_whitelist)
            for address in erc20_bridge_contracts.split(','):
                neon_address = NeonAddress(address)
                if neon_address in airdropper_analyzers:
                    raise Exception(f'Address {neon_address} already specified to analyze')
                airdropper_analyzers[neon_address] = erc20_bridge_analyzer

        self._airdropper = Airdropper(config, faucet_url, wrapper_whitelist, airdropper_analyzers, max_conf)

    def run(self) -> int:
        try:
            self._airdropper.run()
        except BaseException as exc:
            LOG.error('Failed to start Airdropper', exc_info=exc)
            return 1
        return 0
