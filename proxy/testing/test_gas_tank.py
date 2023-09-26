import unittest
import base58

from unittest.mock import patch, call
from typing import Optional, Union

from ..common_neon.config import Config, StartSlot
from ..common_neon.utils import NeonTxInfo
from ..common_neon.address import NeonAddress
from ..common_neon.solana_tx import SolPubKey
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.db.constats_db import ConstantsDB

from ..gas_tank import GasTank
from ..gas_tank.portal_analyzer import PortalAnalyzer
from ..gas_tank.erc20_bridge_analyzer import ERC20Analyzer
from ..gas_tank.neon_pass_analyzer import NeonPassAnalyzer
from ..gas_tank.gas_less_accounts_db import GasLessAccountsDB


from ..testing.transactions import (
    neon_pass_tx, neon_pass_claim_to_ix_data, neon_pass_erc20_for_spl,
    neon_pass_gas_less_account, neon_pass_gas_less_amount,
    erc20_token_mint,
    wormhole_redeem_write_tx, wormhole_redeem_execute_tx, wormhole_write_ix_data,
    wormhole_gas_less_account, wormhole_gas_less_amount, wormhole_contract, wormhole_token_mint
)


class FakeConfig(Config):
    def __init__(self, start_slot: str):
        super().__init__()
        self._start_slot = start_slot
        self._pyth_mapping_account = SolPubKey.new_unique()

    @property
    def pyth_mapping_account(self) -> Optional[SolPubKey]:
        return self._pyth_mapping_account

    @property
    def fuzz_fail_pct(self) -> int:
        return 0


class TestGasTank(unittest.TestCase):
    @classmethod
    def create_gas_tank(cls, start_slot: Union[str, int]) -> GasTank:
        config = FakeConfig(start_slot)
        cls.config = config
        return GasTank(config=config)

    @classmethod
    def add_neon_pass_analyzer(cls, gas_tank: GasTank):
        neon_pass_whitelist = {neon_pass_erc20_for_spl: neon_pass_gas_less_amount}
        neon_pass_analyzer = NeonPassAnalyzer(gas_tank._config, neon_pass_whitelist)
        gas_tank.add_sol_tx_analyzer(neon_pass_analyzer)

    @classmethod
    def add_portal_analyzer(cls, gas_tank: GasTank):
        portal_whitelist = {wormhole_token_mint: wormhole_gas_less_amount}
        portal_analyzer = PortalAnalyzer(gas_tank._config, portal_whitelist)
        gas_tank.add_neon_tx_analyzer(NeonAddress(wormhole_contract), portal_analyzer)

    @classmethod
    def add_erc20_analyzer(cls, gas_tank: GasTank):
        erc20_whitelist = {erc20_token_mint: wormhole_gas_less_amount}
        erc20_analyzer = ERC20Analyzer(gas_tank._config, erc20_whitelist)
        gas_tank.add_neon_tx_analyzer(NeonAddress(wormhole_contract), erc20_analyzer)

    @patch.object(NeonPassAnalyzer, '_is_allowed_contract')
    @patch.object(GasLessAccountsDB, 'add_gas_less_permit_list')
    def test_failed_permit_contract_not_in_whitelist(self, mock_add_gas_less_permit, mock_is_allowed_contract):
        """ Should not permit gas-less txs for contract that is not in whitelist """
        gas_tank = self.create_gas_tank(0)
        gas_tank._current_slot = 1
        self.add_neon_pass_analyzer(gas_tank)
        mock_is_allowed_contract.side_effect = [False]

        gas_tank._process_sol_tx(neon_pass_tx)
        gas_tank._save_cached_data()

        mock_is_allowed_contract.assert_called_once_with(neon_pass_erc20_for_spl, neon_pass_gas_less_amount)
        mock_add_gas_less_permit.assert_not_called()

    @patch.object(GasTank, '_has_gas_less_tx_permit')
    @patch.object(GasLessAccountsDB, 'add_gas_less_permit_list')
    def test_not_permit_for_already_processed_address(self, mock_add_gas_less_permit, mock_has_gas_less_tx_permit):
        """ Should not permit gas-less txs to repeated address """
        gas_tank = self.create_gas_tank(0)
        gas_tank._current_slot = 1
        self.add_neon_pass_analyzer(gas_tank)
        mock_has_gas_less_tx_permit.side_effect = [True]

        gas_tank._process_sol_tx(neon_pass_tx)
        gas_tank._save_cached_data()

        mock_has_gas_less_tx_permit.assert_called_once_with(NeonAddress(neon_pass_gas_less_account))
        mock_add_gas_less_permit.assert_not_called()

    @patch.object(GasTank, '_allow_gas_less_tx')
    def test_neon_pass_simple_case(self, mock_allow_gas_less_tx):
        """ Should allow gas-less txs to liquidity transfer in simple case by NeonPass"""
        gas_tank = self.create_gas_tank(0)
        gas_tank._current_slot = 1
        self.add_neon_pass_analyzer(gas_tank)

        gas_tank._process_sol_tx(neon_pass_tx)
        gas_tank._save_cached_data()

        ix_data = base58.b58decode(neon_pass_claim_to_ix_data)
        neon_tx = NeonTxInfo.from_sig_data(ix_data[5:])

        mock_allow_gas_less_tx.assert_called_once_with(NeonAddress(neon_pass_gas_less_account), neon_tx)

    @patch.object(GasTank, '_allow_gas_less_tx')
    def test_wormhole_transaction_simple_case(self, mock_allow_gas_less_tx):
        """ Should allow gas-less txs to liquidity transfer in simple case by Wormhole"""
        gas_tank = self.create_gas_tank(0)
        gas_tank._current_slot = 2
        self.add_portal_analyzer(gas_tank)

        gas_tank._process_neon_ix(wormhole_redeem_write_tx)
        gas_tank._process_neon_ix(wormhole_redeem_execute_tx)
        gas_tank._save_cached_data()

        ix_data = base58.b58decode(wormhole_write_ix_data)
        neon_tx = NeonTxInfo.from_sig_data(ix_data[41:])

        mock_allow_gas_less_tx.assert_called_once_with(NeonAddress(wormhole_gas_less_account), neon_tx)

    @patch.object(GasTank, '_allow_gas_less_tx')
    def test_erc20_transaction_simple_case(self, mock_allow_gas_less_tx):
        """ Should allow gas-less txs to liquidity transfer in simple case by ERC20"""
        gas_tank = self.create_gas_tank(0)
        gas_tank._current_slot = 2
        self.add_erc20_analyzer(gas_tank)

        gas_tank._process_neon_ix(wormhole_redeem_write_tx)
        gas_tank._process_neon_ix(wormhole_redeem_execute_tx)
        gas_tank._save_cached_data()

        ix_data = base58.b58decode(wormhole_write_ix_data)
        neon_tx = NeonTxInfo.from_sig_data(ix_data[41:])

        mock_allow_gas_less_tx.assert_called_once_with(NeonAddress(wormhole_gas_less_account), neon_tx)

    @patch.object(ConstantsDB, 'get')
    @patch.object(SolInteractor, 'get_block_slot')
    def test_init_gas_tank_slot_continue(self, mock_get_slot, mock_dict_get):
        start_slot = 1234
        mock_dict_get.side_effect = [start_slot - 1]
        mock_get_slot.side_effect = [start_slot + 1]

        new_gas_tank = self.create_gas_tank(StartSlot.Continue)

        self.assertEqual(new_gas_tank._latest_gas_tank_slot, start_slot - 1)
        mock_get_slot.assert_called_once_with('finalized')
        mock_dict_get.assert_called()

    @patch.object(ConstantsDB, 'get')
    @patch.object(SolInteractor, 'get_block_slot')
    def test_init_gas_tank_slot_continue_recent_slot_not_found(self, mock_get_slot, mock_dict_get):
        start_slot = 1234
        mock_dict_get.side_effect = [None]
        mock_get_slot.side_effect = [start_slot + 1]

        new_gas_tank = self.create_gas_tank(StartSlot.Continue)

        self.assertEqual(new_gas_tank._latest_gas_tank_slot, start_slot + 1)
        mock_get_slot.assert_called_once_with('finalized')
        mock_dict_get.assert_called()

    @patch.object(ConstantsDB, 'get')
    @patch.object(SolInteractor, 'get_block_slot')
    def test_init_gas_tank_start_slot_parse_error(self, mock_get_slot, mock_dict_get):
        start_slot = 1234
        mock_dict_get.side_effect = [start_slot - 1]
        mock_get_slot.side_effect = [start_slot + 1]

        new_gas_tank = self.create_gas_tank('Wrong value')

        self.assertEqual(new_gas_tank._latest_gas_tank_slot, start_slot - 1)
        mock_get_slot.assert_called_once_with('finalized')
        mock_dict_get.assert_called()

    @patch.object(ConstantsDB, 'get')
    @patch.object(SolInteractor, 'get_block_slot')
    def test_init_gas_tank_slot_latest(self, mock_get_slot, mock_dict_get):
        start_slot = 1234
        mock_dict_get.side_effect = [start_slot - 1]
        mock_get_slot.side_effect = [start_slot + 1]

        new_gas_tank = self.create_gas_tank(StartSlot.Latest)

        self.assertEqual(new_gas_tank._latest_gas_tank_slot, start_slot + 1)
        mock_get_slot.assert_called_once_with('finalized')
        mock_dict_get.assert_called()

    @patch.object(ConstantsDB, 'get')
    @patch.object(SolInteractor, 'get_block_slot')
    def test_init_gas_tank_slot_number(self, mock_get_slot, mock_dict_get):
        start_slot = 1234
        mock_dict_get.side_effect = [start_slot - 1]
        mock_get_slot.side_effect = [start_slot + 1]

        new_gas_tank = self.create_gas_tank(start_slot)

        self.assertEqual(new_gas_tank._latest_gas_tank_slot, start_slot)
        mock_get_slot.assert_called_once_with('finalized')
        mock_dict_get.assert_called()

    @patch.object(ConstantsDB, 'get')
    @patch.object(SolInteractor, 'get_block_slot')
    def test_init_gas_tank_big_slot_number(self, mock_get_slot, mock_dict_get):
        start_slot = 1234
        mock_dict_get.side_effect = [start_slot - 1]
        mock_get_slot.side_effect = [start_slot + 1]

        new_gas_tank = self.create_gas_tank(start_slot + 100)

        self.assertEqual(new_gas_tank._latest_gas_tank_slot, start_slot + 1)
        mock_get_slot.assert_called_once_with('finalized')
        mock_dict_get.assert_called()
