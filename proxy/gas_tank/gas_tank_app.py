import os
import logging
from typing import Dict, Type, Union

from ..common_neon.address import NeonAddress
from ..common_neon.config import Config
from ..common.logger import Logger

from .gas_tank import GasTank, GasTankNeonTxAnalyzer, GasTankSolTxAnalyzer
from .portal_analyzer import PortalAnalyzer
from .erc20_bridge_analyzer import ERC20Analyzer
from .neon_pass_analyzer import NeonPassAnalyzer


LOG = logging.getLogger(__name__)


class GasTankApp:
    def __init__(self):
        Logger.setup()
        LOG.info('GasTank application is starting ...')
        self._config = Config()
        LOG.info(f'Construct GasTank with params: {str(self._config)}')

        self._gas_tank = GasTank(self._config)
        self._get_sol_tx_analyzer_cfg('INDEXER_ERC20_WRAPPER_WHITELIST', NeonPassAnalyzer)
        self._get_neon_tx_analyzer_cfg('PORTAL_BRIDGE_CONTRACTS', 'PORTAL_BRIDGE_TOKENS_WHITELIST', PortalAnalyzer)
        self._get_neon_tx_analyzer_cfg('ERC20_BRIDGE_CONTRACTS', 'ERC20_BRIDGE_TOKENS_WHITELIST', ERC20Analyzer)

    def _get_sol_tx_analyzer_cfg(self, env_contract_whitelist: str,
                                 AnalyzerType: Type[GasTankSolTxAnalyzer]) -> None:
        raw_token_whitelist = os.environ.get(env_contract_whitelist, None)
        if raw_token_whitelist is None:
            LOG.info(f'No configuration for {AnalyzerType.name}')
            return

        token_whitelist: Union[bool, Dict[str, int]] = self._get_token_whitelist(raw_token_whitelist)
        sol_tx_analyzer = AnalyzerType(self._config, token_whitelist)
        self._gas_tank.add_sol_tx_analyzer(sol_tx_analyzer)

    def _get_neon_tx_analyzer_cfg(self, env_bridge_contract_name: str,
                                  env_token_whitelist_name: str,
                                  AnalyzerType: Type[GasTankNeonTxAnalyzer]) -> None:
        raw_contract_list = os.environ.get(env_bridge_contract_name, None)
        raw_token_whitelist = os.environ.get(env_token_whitelist_name, None)
        if (raw_contract_list is None) != (raw_token_whitelist is None):
            raise RuntimeError(
                f'Need to specify both {env_bridge_contract_name} & {env_token_whitelist_name} environment variables'
            )

        elif raw_contract_list is None:
            return

        token_whitelist: Union[bool, Dict[str, int]] = self._get_token_whitelist(raw_token_whitelist)
        neon_tx_analyzer = AnalyzerType(self._config, token_whitelist)
        if raw_contract_list == 'ANY':
            self._gas_tank.add_neon_tx_analyzer(True, neon_tx_analyzer)
            return

        for address in raw_contract_list.split(','):
            self._gas_tank.add_neon_tx_analyzer(NeonAddress(address), neon_tx_analyzer)

    @staticmethod
    def _get_token_whitelist(raw_token_whitelist: str) -> Union[bool, Dict[str, int]]:
        if raw_token_whitelist == 'ANY':
            return True

        token_whitelist: Dict[str, int] = dict()
        for token_amount in raw_token_whitelist.split(','):
            if token_amount.find(':') != -1:
                token, amount = token_amount.split(':')
                amount = int(amount)
            else:
                token, amount = token_amount, 0
            token_whitelist[token] = amount
        return token_whitelist

    def run(self) -> int:
        try:
            self._gas_tank.run()
        except BaseException as exc:
            LOG.error('Failed to start GasTank', exc_info=exc)
            return 1
        return 0
