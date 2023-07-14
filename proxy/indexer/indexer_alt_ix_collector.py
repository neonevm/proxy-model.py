from __future__ import annotations

import logging

from typing import List, Dict, Any

from ..common_neon.solana_tx import SolPubKey, SolCommit
from ..common_neon.layouts import ALTAccountInfo
from ..common_neon.solana_neon_tx_receipt import SolAltIxInfo, SolTxMetaInfo, SolIxMetaInfo
from ..common_neon.constants import ADDRESS_LOOKUP_TABLE_ID
from ..common_neon.config import Config
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.neon_instruction import AltIxCode

from .indexed_objects import NeonIndexedBlockInfo, NeonIndexedAltInfo


LOG = logging.getLogger(__name__)


class AltIxCollector:
    _block_step_cnt = 32

    def __init__(self, config: Config, solana: SolInteractor):
        self._config = config
        self._solana = solana
        self._next_check_slot = self._block_step_cnt

    def collect_in_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        if neon_block.block_slot < self._next_check_slot:
            return

        next_check_slot = neon_block.block_slot + self._block_step_cnt
        fail_check_slot = neon_block.block_slot - self._config.alt_freeing_depth * 10

        self._next_check_slot = next_check_slot

        for alt_info in list(neon_block.iter_alt_info()):
            if alt_info.next_check_slot == 0:
                alt_info.set_next_check_slot(next_check_slot)
                continue
            elif alt_info.next_check_slot > neon_block.block_slot:
                continue
            alt_info.set_next_check_slot(next_check_slot)

            decode_result = AltIxListDecoder(self._solana, alt_info).decode()
            if decode_result.is_done:
                neon_block.done_alt_info(alt_info, decode_result.alt_ix_list)
            elif (alt_info.block_slot < fail_check_slot) and self._is_done_alt(alt_info):
                neon_block.done_alt_info(alt_info, decode_result.alt_ix_list)
            else:
                neon_block.add_alt_ix_list(alt_info, decode_result.alt_ix_list)

    def _is_done_alt(self, alt_info: NeonIndexedAltInfo) -> bool:
        alt_address = SolPubKey.from_string(alt_info.alt_key)
        acct_info = self._solana.get_account_info(alt_address, commitment=SolCommit.Finalized)
        if acct_info is None:
            return True

        alt_acct_info = ALTAccountInfo.from_account_info(acct_info)
        if alt_acct_info is None:
            return True
        elif alt_acct_info.authority is None:
            LOG.warning(f'ALT {alt_info.alt_key} is frozen')
            return True

        if alt_acct_info.authority in self._config.operator_account_set:
            return False

        # don't wait for ALTs from other operators
        return True


class AltIxListDecoder:
    def __init__(self, solana: SolInteractor, alt_info: NeonIndexedAltInfo):
        self._solana = solana
        self._alt_info = alt_info
        self._tx_receipt_list: List[Dict[str, Any]] = list()
        self.is_done = False
        self.alt_ix_list: List[SolAltIxInfo] = list()

    def decode(self) -> AltIxListDecoder:
        self._get_tx_receipt_list()
        self._decode_alt_ix_list()
        return self

    def _get_tx_receipt_list(self) -> None:
        sig_block_list = self._solana.get_sig_list_for_address(self._alt_info.alt_key, None, 1000, SolCommit.Finalized)
        sig_list: List[str] = list()
        for sig_block in sig_block_list:
            if sig_block.get('slot') > self._alt_info.last_ix_slot:
                sig_list.append(sig_block.get('signature'))
        self._tx_receipt_list = self._solana.get_tx_receipt_list(sig_list, SolCommit.Finalized)

    def _decode_alt_ix_list(self):
        for tx_receipt in self._tx_receipt_list:
            if tx_receipt is None:
                LOG.warning(f'No transaction receipt for {str(self._alt_info)}')
                continue

            tx_meta = SolTxMetaInfo.from_tx_receipt(None, tx_receipt)
            for ix_meta in tx_meta.ix_meta_list:
                self._decode_alt_ix(ix_meta)

                for inner_ix_meta in tx_meta.inner_ix_meta_list(ix_meta):
                    self._decode_alt_ix(inner_ix_meta)

    def _decode_alt_ix(self, ix_meta: SolIxMetaInfo) -> None:
        if not ix_meta.is_program(ADDRESS_LOOKUP_TABLE_ID):
            return

        try:
            ix_data = ix_meta.ix_data
            ix_code = int.from_bytes(ix_data[:4], 'little')
        except BaseException as exc:
            LOG.warning(f'failed to decode ALT instruction data in Solana ix {str(ix_meta)}', exc_info=exc)
            return

        if ix_code == AltIxCode.Freeze:
            LOG.warning(f'ALT {str(self._alt_info)} is frozen')
            self.is_done = True
        elif ix_code == AltIxCode.Close:
            self.is_done = True

        alt_ix_info = SolAltIxInfo.from_ix_meta(ix_meta, ix_code, self._alt_info.alt_key, self._alt_info.neon_tx_sig)
        self.alt_ix_list.append(alt_ix_info)
