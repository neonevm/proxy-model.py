from __future__ import annotations

import logging
from typing import Dict, Any, Union, List, Tuple

from .gas_less_accounts_db import GasLessAccountsDB
from .gas_less_usages_db import GasLessUsagesDB
from .gas_tank_types import GasTankNeonTxAnalyzer, GasTankSolTxAnalyzer, GasTankTxInfo, GasLessPermit, GasLessUsage

from ..common_neon.address import NeonAddress
from ..common_neon.config import Config
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_neon_tx_receipt import SolTxReceiptInfo, SolNeonIxReceiptInfo
from ..common_neon.utils.json_logger import logging_context
from ..common_neon.utils.neon_tx_info import NeonTxInfo

from ..indexer.indexed_objects import NeonIndexedHolderInfo
from ..indexer.indexer_base import IndexerBase
from ..indexer.solana_tx_meta_collector import SolTxMetaDict, FinalizedSolTxMetaCollector
from ..indexer.sql_dict import SQLDict
from ..indexer.utils import MetricsToLogger


LOG = logging.getLogger(__name__)

EVM_PROGRAM_HOLDER_WRITE = 0x26

EVM_PROGRAM_CALL_FROM_DATA = 0x1f
EVM_PROGRAM_CALL_FROM_ACCOUNT = 0x2A

EVM_PROGRAM_TX_STEP_FROM_DATA = 0x20
EVM_PROGRAM_TX_STEP_FROM_ACCOUNT = 0x21
EVM_PROGRAM_TX_STEP_FROM_ACCOUNT_NO_CHAINID = 0x22

EVM_PROGRAM_CANCEL = 0x23


class GasTank(IndexerBase):
    def __init__(self, config: Config):
        self._constants = SQLDict(tablename='constants')

        solana = SolInteractor(config, config.solana_url)
        last_known_slot = self._constants.get('latest_gas_tank_slot', None)
        super().__init__(config, solana, last_known_slot)
        self._last_block_slot = self._start_slot
        self._latest_gas_tank_slot = self._start_slot
        self._current_slot = 0

        self._counted_logger = MetricsToLogger()

        sol_tx_meta_dict = SolTxMetaDict()
        self._sol_tx_collector = FinalizedSolTxMetaCollector(config, self._solana, sol_tx_meta_dict, self._start_slot)

        self._gas_less_account_db = GasLessAccountsDB()
        self._gas_less_account_dict: Dict[str, GasLessPermit] = dict()

        self._gas_less_usage_db = GasLessUsagesDB()
        self._gas_less_usage_list: List[GasLessUsage] = list()

        self._neon_large_tx_dict: Dict[str, NeonIndexedHolderInfo] = dict()
        self._neon_processed_tx_dict: Dict[str, GasTankTxInfo] = dict()
        self._last_finalized_slot: int = 0

        self._neon_tx_analyzer_dict: Dict[Union[NeonAddress, bool], GasTankNeonTxAnalyzer] = dict()
        self._sol_tx_analyzer_dict: Dict[str, GasTankSolTxAnalyzer] = dict()

    def add_sol_tx_analyzer(self, sol_tx_analyzer: GasTankSolTxAnalyzer) -> None:
        if sol_tx_analyzer.name in self._sol_tx_analyzer_dict:
            raise RuntimeError(f'Analyzer {sol_tx_analyzer.name} is already specified to analyze Solana txs')
        self._sol_tx_analyzer_dict[sol_tx_analyzer.name] = sol_tx_analyzer

    def add_neon_tx_analyzer(self, address: Union[NeonAddress, bool], neon_tx_analyzer: GasTankNeonTxAnalyzer) -> None:
        if address in self._neon_large_tx_dict:
            raise RuntimeError(f'Address {neon_tx_analyzer.name} is already specified to analyze Neon txs')

        self._neon_tx_analyzer_dict[address] = neon_tx_analyzer

    # Method to process NeonEVM transaction extracted from the instructions
    def _process_neon_tx(self, tx_info: GasTankTxInfo) -> None:
        if tx_info.status != GasTankTxInfo.Status.Done or tx_info.neon_tx_res.status != '0x1':
            LOG.debug(f'SKIPPED {tx_info.key} status {tx_info.status} result {tx_info.neon_tx_res.status}: {tx_info}')
            return

        try:
            tx_info.finalize()

            self._process_neon_tx_analyzer(tx_info)
            self._process_gas_less_tx(tx_info)

        except Exception as error:
            LOG.warning(f'failed to process {tx_info.key}: {str(error)}')

    def _process_neon_tx_analyzer(self, tx_info: GasTankTxInfo) -> None:
        neon_tx = tx_info.neon_tx
        if neon_tx.to_addr is None:
            return

        sender = neon_tx.addr
        to = NeonAddress(neon_tx.to_addr)
        LOG.debug(f'from: {sender}, to: {to}')

        neon_tx_analyzer = self._neon_tx_analyzer_dict.get(to, None)
        if neon_tx_analyzer is None:
            neon_tx_analyzer = self._neon_tx_analyzer_dict.get(True, None)
            if neon_tx_analyzer is None:
                return

        LOG.debug(f'trying NeonTx analyzer {neon_tx_analyzer.name} ...')
        account = neon_tx_analyzer.process(tx_info)
        if account is None:
            LOG.debug(f'NeonTx analyzer {neon_tx_analyzer.name} failed')
            return
        LOG.debug(f'NeonTx analyzer {neon_tx_analyzer.name} success')
        self._allow_gas_less_tx(account, neon_tx)

    def _process_gas_less_tx(self, tx_info: GasTankTxInfo) -> None:
        neon_tx = tx_info.neon_tx
        if neon_tx.gas_price != '0x0':
            return

        LOG.debug(f'gas-less tx: {neon_tx}')

        gas_less_usage = GasLessUsage(
            account=NeonAddress(neon_tx.addr),
            block_slot=self._current_slot,
            neon_sig=neon_tx.sig,
            nonce=int(neon_tx.nonce[2:], 16),
            to_addr=NeonAddress(neon_tx.to_addr) if neon_tx.to_addr is not None else None,
            neon_total_gas_usage=int(tx_info.neon_tx_res.gas_used[2:], 16),
            operator=tx_info.operator
        )
        self._gas_less_usage_list.append(gas_less_usage)
        if len(self._gas_less_usage_list) > 1000:
            self._save_cached_data()

    def _process_write_holder_ix(self, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        neon_tx_id = NeonIndexedHolderInfo.Key(sol_neon_ix.get_account(0), sol_neon_ix.neon_tx_sig)
        data = sol_neon_ix.ix_data[41:]
        chunk = NeonIndexedHolderInfo.DataChunk(
            offset=int.from_bytes(sol_neon_ix.ix_data[33:41], 'little'),
            length=len(data),
            data=data
        )
        neon_tx_data = self._neon_large_tx_dict.get(neon_tx_id.value, None)
        if neon_tx_data is None:
            LOG.debug(f'new NEON tx: {neon_tx_id} {len(chunk.data)} bytes at {chunk.offset}')
            neon_tx_data = NeonIndexedHolderInfo(neon_tx_id)
            self._neon_large_tx_dict[neon_tx_id.value] = neon_tx_data
        neon_tx_data.add_data_chunk(chunk)
        neon_tx_data.add_sol_neon_ix(sol_neon_ix)

    def _process_step_ix(self, sol_neon_ix: SolNeonIxReceiptInfo, ix_code: int) -> None:
        key = GasTankTxInfo.Key(sol_neon_ix)
        tx_info = self._neon_processed_tx_dict.get(key.value, None)
        if tx_info is not None:
            tx_info.append_receipt(sol_neon_ix)
            return

        neon_tx_id = NeonIndexedHolderInfo.Key(sol_neon_ix.get_account(0), sol_neon_ix.neon_tx_sig)
        neon_tx_data = self._neon_large_tx_dict.pop(neon_tx_id.value, None)
        if neon_tx_data is None:
            LOG.warning(f'holder account {neon_tx_id} is not in the collected data')
            return

        tx_type = GasTankTxInfo.Type(ix_code)
        first_blocked_account = 6
        tx_info = GasTankTxInfo.create_tx_info(
            sol_neon_ix.neon_tx_sig, neon_tx_data.data, tx_type, key,
            sol_neon_ix.sol_tx_cost.operator,
            sol_neon_ix.get_account(0), sol_neon_ix.iter_account(first_blocked_account)
        )
        if tx_info is None:
            return
        tx_info.append_receipt(sol_neon_ix)

        if ix_code == EVM_PROGRAM_CALL_FROM_ACCOUNT:
            if tx_info.status != GasTankTxInfo.Status.Done:
                LOG.warning('no tx_return for single call')
            else:
                self._process_neon_tx(tx_info)
        else:
            self._neon_processed_tx_dict[key.value] = tx_info

    def _process_call_raw_tx(self, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        if len(sol_neon_ix.ix_data) < 6:
            LOG.warning('no enough data to get Neon tx')
            return

        tx_info = GasTankTxInfo.create_tx_info(
            sol_neon_ix.neon_tx_sig, sol_neon_ix.ix_data[5:],
            GasTankTxInfo.Type.Single, GasTankTxInfo.Key(sol_neon_ix),
            sol_neon_ix.sol_tx_cost.operator, '', iter(())
        )
        if tx_info is None:
            return
        tx_info.append_receipt(sol_neon_ix)

        if tx_info.status != GasTankTxInfo.Status.Done:
            LOG.warning('no tx_return for single call')
            return

        self._process_neon_tx(tx_info)

    def _process_call_raw_nochain_id_tx(self, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        key = GasTankTxInfo.Key(sol_neon_ix)
        tx_info = self._neon_processed_tx_dict.get(key.value, None)
        if tx_info is None:
            first_blocked_account = 6
            if len(sol_neon_ix.ix_data) < 14 or sol_neon_ix.account_cnt < first_blocked_account + 1:
                LOG.warning('no enough data or accounts to get Neon tx')
                return

            tx_info = GasTankTxInfo.create_tx_info(
                sol_neon_ix.neon_tx_sig, sol_neon_ix.ix_data[13:],
                GasTankTxInfo.Type.IterFromData, key,
                sol_neon_ix.sol_tx_cost.operator,
                sol_neon_ix.get_account(0), sol_neon_ix.iter_account(first_blocked_account)
            )
            if tx_info is None:
                return
            self._neon_processed_tx_dict[key.value] = tx_info

        tx_info.append_receipt(sol_neon_ix)

    def _process_cancel(self, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        key = GasTankTxInfo.Key(sol_neon_ix)
        tx_info = self._neon_processed_tx_dict.get(key.value, None)
        if tx_info is None:
            LOG.warning(f'cancel unknown trx {key}')
            return
        tx_info.set_status(GasTankTxInfo.Status.Canceled, sol_neon_ix.block_slot)

    def _process_finalized_tx_list(self, block_slot: int) -> None:
        if self._last_finalized_slot >= block_slot:
            return

        self._last_finalized_slot = block_slot
        finalized_tx_list = [
            k for k, v in self._neon_processed_tx_dict.items() if
            v.status != GasTankTxInfo.Status.InProgress and v.last_block_slot < block_slot
        ]
        if not len(finalized_tx_list):
            return

        LOG.debug(f'finalized: {finalized_tx_list}')
        for k in finalized_tx_list:
            tx_info = self._neon_processed_tx_dict.pop(k)
            self._process_neon_tx(tx_info)

    # Method to process Solana transactions and extract NeonEVM transaction from the contract instructions.
    # For large NeonEVM transaction that passing to contract via account data, this method extracts and
    # combines chunk of data from different HolderWrite instructions. At any time `neon_large_tx`
    # dictionary contains actual NeonEVM transactions written into the holder accounts. The stored account
    # are cleared in case of execution, cancel trx or writing chunk of data from another NeonEVM transaction.
    # This logic are implemented according to the work with holder account inside contract.
    # Note: the `neon_large_tx` dictionary stored only in memory, so `last_processed_slot` move forward only
    # after finalize corresponding holder account. It is necessary for correct transaction processing after
    # restart the gas-tank service.
    # Note: this implementation analyzes only the final step in case of iterative execution. It simplifies it
    # but does not process events generated from the Solidity contract.
    def _process_neon_ix(self, tx: Dict[str, Any]):
        tx_receipt_info = SolTxReceiptInfo.from_tx_receipt(tx)

        self._process_finalized_tx_list(tx_receipt_info.block_slot)

        for sol_neon_ix in tx_receipt_info.iter_sol_ix(self._config.evm_program_id):
            ix_code = sol_neon_ix.ix_data[0]
            LOG.debug(f'instruction: {ix_code} {sol_neon_ix.neon_tx_sig}')
            if ix_code == EVM_PROGRAM_HOLDER_WRITE:
                self._process_write_holder_ix(sol_neon_ix)

            elif ix_code in {EVM_PROGRAM_TX_STEP_FROM_ACCOUNT,
                             EVM_PROGRAM_TX_STEP_FROM_ACCOUNT_NO_CHAINID,
                             EVM_PROGRAM_CALL_FROM_ACCOUNT}:
                self._process_step_ix(sol_neon_ix, ix_code)

            elif ix_code == EVM_PROGRAM_CALL_FROM_DATA:
                self._process_call_raw_tx(sol_neon_ix)

            elif ix_code == EVM_LOADER_TX_STEP_FROM_DATA:
                self._process_call_raw_nochain_id_tx(sol_neon_ix)

            elif ix_code == EVM_PROGRAM_CANCEL:
                self._process_cancel(sol_neon_ix)

    def _has_gas_less_tx_permit(self, account: NeonAddress) -> bool:
        if str(account) in self._gas_less_account_dict:
            return True
        elif self._gas_less_account_db.has_gas_less_tx_permit(account):
            return True
        return False

    def _allow_gas_less_tx(self, account: NeonAddress, neon_tx: NeonTxInfo) -> None:
        if self._has_gas_less_tx_permit(account):
            # Target account already supplied with gas-less transactions
            return

        self._gas_less_account_dict[str(account)] = GasLessPermit(account, self._current_slot, neon_tx.sig)
        LOG.debug(f'set gas less permit to {str(account)}')
        if len(self._gas_less_account_dict) > 1000:
            self._save_cached_data()

    def process_functions(self) -> None:
        """
        Overrides IndexerBase.process_functions
        """
        super().process_functions()
        self._process_receipts()

    def _process_sol_tx(self, tx: Dict[str, Any]) -> bool:
        for sol_analyzer in self._sol_tx_analyzer_dict.values():
            LOG.debug(f'trying SolTx analyzer {sol_analyzer.name}...')
            approved_list: List[Tuple[NeonAddress, NeonTxInfo]] = sol_analyzer.process(tx)
            if len(approved_list) == 0:
                LOG.debug(f'SolTx analyzer {sol_analyzer.name} failed')
                continue

            for account, neon_tx in approved_list:
                self._allow_gas_less_tx(account, neon_tx)
            return True

        return False

    def _process_receipts(self) -> None:
        last_block_slot = self._solana.get_block_slot(self._sol_tx_collector.commitment)
        if self._last_block_slot >= last_block_slot:
            return
        self._last_block_slot = last_block_slot

        for meta in self._sol_tx_collector.iter_tx_meta(last_block_slot, self._sol_tx_collector.last_block_slot):
            self._current_slot = meta.block_slot
            if self._check_error(meta.tx):
                continue

            with logging_context(sol_sig=meta.sol_sig):
                if not self._process_sol_tx(meta.tx):
                    self._process_neon_ix(meta.tx)

        self._save_cached_data()
        self._clear_old_data()

        with logging_context(ident='stat'):
            self._counted_logger.print(
                self._config,
                list_value_dict={},
                latest_value_dict={
                    'Latest slot': self._last_block_slot,
                    'Latest processed slot': self._latest_gas_tank_slot,
                    'Solana finalized slot': self._sol_tx_collector.last_block_slot
                }
            )

    @staticmethod
    def _check_error(tx: Dict[str, Any]) -> bool:
        if 'meta' not in tx:
            return False

        meta = tx['meta']
        if 'err' not in meta:
            return False

        err = meta['err']
        if err is None:
            return False

        return True

    def _clear_old_data(self) -> None:
        self._latest_gas_tank_slot = self._sol_tx_collector.last_block_slot

        # Find the minimum start_block_slot through unfinished neon_large_tx. It is necessary for correct
        # transaction processing after restart the gas-tank service. See `_process_neon_ix`
        # for more information.
        outdated_holder_list = [
            tx.key for tx in self._neon_large_tx_dict.values()
            if tx.last_block_slot + self._config.holder_timeout < self._sol_tx_collector.last_block_slot
        ]
        for tx_key in outdated_holder_list:
            LOG.info(f'Outdated holder {tx_key}. Drop it.')
            self._neon_large_tx_dict.pop(tx_key)

        lost_tx_list = [
            k for k, v in self._neon_processed_tx_dict.items()
            if v.status == GasTankTxInfo.Status.InProgress
            and v.last_block_slot + self._config.holder_timeout < self._sol_tx_collector.last_block_slot
        ]
        for k in lost_tx_list:
            tx_info = self._neon_processed_tx_dict.pop(k)
            LOG.warning(f'Lost trx {tx_info.key}. Drop it.')

        for tx in self._neon_large_tx_dict.values():
            self._latest_gas_tank_slot = min(self._latest_gas_tank_slot, tx.start_block_slot - 1)
        for tx in self._neon_processed_tx_dict.values():
            self._latest_gas_tank_slot = min(self._latest_gas_tank_slot, tx.start_block_slot - 1)

        self._constants['latest_gas_tank_slot'] = self._latest_gas_tank_slot

    def _save_cached_data(self) -> None:
        if (len(self._gas_less_account_dict) == 0) and (len(self._gas_less_usage_list) == 0):
            return

        with self._gas_less_account_db.conn() as conn:
            with conn.cursor() as cursor:
                self._gas_less_account_db.add_gas_less_permit_list(cursor, iter(self._gas_less_account_dict.values()))
                self._gas_less_account_dict.clear()
                self._gas_less_usage_db.add_gas_less_usage_list(cursor, iter(self._gas_less_usage_list))
                self._gas_less_usage_list.clear()