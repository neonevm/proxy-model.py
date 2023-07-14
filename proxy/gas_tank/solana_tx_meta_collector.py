from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from multiprocessing.dummy import Pool as ThreadPool
from typing import Optional, Dict, Iterator, List, Any

from proxy.common_neon.config import Config
from proxy.common_neon.solana_tx import SolCommit
from proxy.common_neon.solana_interactor import SolInteractor
from proxy.common_neon.solana_neon_tx_receipt import SolTxMetaInfo, SolTxSigSlotInfo
from proxy.common_neon.db.db_connect import DBConnection


from proxy.indexer.solana_signatures_db import SolSigsDB


LOG = logging.getLogger(__name__)


class SolHistoryNotFound(RuntimeError):
    pass


class SolTxMetaDict:
    def __init__(self):
        self._tx_meta_dict: Dict[SolTxSigSlotInfo, SolTxMetaInfo] = {}

    def has_sig(self, sig_slot: SolTxSigSlotInfo) -> bool:
        return sig_slot in self._tx_meta_dict

    def add(self, sig_slot: SolTxSigSlotInfo, tx_receipt: Dict[str, Any]) -> None:
        if tx_receipt is None:
            raise SolHistoryNotFound(f'Solana receipt {sig_slot} not found')

        block_slot = tx_receipt['slot']
        sol_sig = tx_receipt['transaction']['signatures'][0]
        if block_slot != sig_slot.block_slot:
            raise SolHistoryNotFound(f'Solana receipt {sig_slot} on another history branch: {sol_sig}:{block_slot}')
        self._tx_meta_dict[sig_slot] = SolTxMetaInfo.from_tx_receipt(block_slot, tx_receipt)

    def get(self, sig_slot: SolTxSigSlotInfo) -> Optional[SolTxMetaInfo]:
        tx_meta = self._tx_meta_dict.get(sig_slot, None)
        if tx_meta is None:
            raise SolHistoryNotFound(f'no Solana receipt for the signature: {sig_slot}')
        return tx_meta

    def pop(self, sig_slot: SolTxSigSlotInfo) -> Optional[SolTxMetaInfo]:
        return self._tx_meta_dict.pop(sig_slot, None)

    def keys(self) -> List[SolTxSigSlotInfo]:
        return list(self._tx_meta_dict.keys())


class SolTxMetaCollector(ABC):
    def __init__(self, config: Config,
                 solana: SolInteractor,
                 tx_meta_dict: SolTxMetaDict,
                 commitment: SolCommit.Type,
                 is_finalized: bool):
        self._solana = solana
        self._config = config
        self._commitment = commitment
        self._is_finalized = is_finalized
        self._tx_meta_dict = tx_meta_dict
        self._thread_pool = ThreadPool(config.gas_tank_parallel_request_cnt)

    @property
    def commitment(self) -> str:
        return self._commitment

    @property
    def is_finalized(self) -> bool:
        return self._is_finalized

    @abstractmethod
    def iter_tx_meta(self, start_slot: int, stop_slot: int) -> Iterator[SolTxMetaInfo]:
        pass

    def _iter_tx_meta(self, sig_slot_list: List[SolTxSigSlotInfo]) -> Iterator[SolTxMetaInfo]:
        group_len = 20
        filtered_sig_slot_list = [sig_slot for sig_slot in sig_slot_list if not self._tx_meta_dict.has_sig(sig_slot)]
        flat_len = len(filtered_sig_slot_list)
        grouped_sig_slot_list = [filtered_sig_slot_list[i:(i + group_len)] for i in range(0, flat_len, group_len)]
        self._gather_tx_meta_dict(grouped_sig_slot_list)
        for sig_slot in reversed(sig_slot_list):
            yield self._tx_meta_dict.get(sig_slot)

    def _gather_tx_meta_dict(self, grouped_sig_slot_list: List[List[SolTxSigSlotInfo]]) -> None:
        if len(grouped_sig_slot_list) > 1:
            self._thread_pool.map(self._request_tx_meta_list, grouped_sig_slot_list)
        elif len(grouped_sig_slot_list) > 0:
            self._request_tx_meta_list(grouped_sig_slot_list[0])

    def _request_tx_meta_list(self, sig_slot_list: List[SolTxSigSlotInfo]) -> None:
        sig_list = [sig_slot.sol_sig for sig_slot in sig_slot_list]
        meta_list = self._solana.get_tx_receipt_list(sig_list, commitment=self._commitment)
        for sig_slot, tx_meta in zip(sig_slot_list, meta_list):
            self._tx_meta_dict.add(sig_slot, tx_meta)

    def _iter_sig_slot(self, start_sig: Optional[str], start_slot: int, stop_slot: int) -> Iterator[SolTxSigSlotInfo]:
        response_list_len = 1
        while response_list_len:
            response_list = self._solana.get_sig_list_for_address(
                self._config.evm_program_id,
                start_sig, self._config.gas_tank_poll_tx_cnt, self._commitment
            )
            response_list_len = len(response_list)
            if response_list_len == 0:
                return
            start_sig = response_list[-1]["signature"]

            for response in response_list:
                block_slot = response['slot']
                if block_slot > start_slot:
                    continue
                elif block_slot < stop_slot:
                    return

                yield SolTxSigSlotInfo(block_slot=block_slot, sol_sig=response['signature'])


class FinalizedSolTxMetaCollector(SolTxMetaCollector):
    def __init__(self, db: DBConnection, config: Config, solana: SolInteractor,
                 tx_meta_dict: SolTxMetaDict, stop_slot: int):
        super().__init__(config, solana, tx_meta_dict, commitment=SolCommit.Finalized, is_finalized=True)
        LOG.debug(f'Finalized commitment: {self._commitment}')
        self._sigs_db = SolSigsDB(db)
        self._stop_slot = stop_slot
        self._sig_cnt = 0
        self._last_info: Optional[SolTxSigSlotInfo] = None

    @property
    def last_block_slot(self) -> int:
        return self._stop_slot

    def _build_checkpoint_list(self, start_slot: int) -> None:
        max_sig = self._sigs_db.get_max_sig()
        stop_slot = max(max_sig.block_slot, self._stop_slot) if max_sig else self._stop_slot
        self._stop_slot = stop_slot
        for info in self._iter_sig_slot(None, start_slot, stop_slot):
            self._save_checkpoint(info)

    def _save_checkpoint(self, info: SolTxSigSlotInfo, cnt: int = 1) -> None:
        self._sig_cnt += cnt
        if self._sig_cnt < self._config.gas_tank_poll_tx_cnt:
            return
        elif self._last_info is None or self._last_info.block_slot == info.block_slot:
            self._last_info = info
        elif self._last_info.block_slot != info.block_slot:
            LOG.debug(f'save checkpoint: {self._last_info}: {self._sig_cnt}')
            self._sigs_db.add_sig(self._last_info)
            self._reset_checkpoint_cache()

    def _reset_checkpoint_cache(self) -> None:
        self._last_info = None
        self._sig_cnt = 0

    def _iter_sig_slot_list(self, start_slot: int, is_long_list: bool) -> Iterator[List[SolTxSigSlotInfo]]:
        start_sig: Optional[str] = ''
        next_info: Optional[SolTxSigSlotInfo] = None
        while start_sig is not None:
            start_sig = None
            if is_long_list:
                next_info = self._sigs_db.get_next_sig(self._stop_slot)
                if next_info:
                    start_sig = next_info.sol_sig

            sig_slot_list = list(self._iter_sig_slot(start_sig, start_slot, self._stop_slot))
            sig_slot_list_len = len(sig_slot_list)
            if sig_slot_list_len == 0:
                if next_info is not None:
                    self._stop_slot = next_info.block_slot
                    continue
                return

            if next_info is None:
                self._stop_slot = sig_slot_list[0].block_slot + 1
            else:
                self._stop_slot = next_info.block_slot

            if not is_long_list:
                self._save_checkpoint(sig_slot_list[0], sig_slot_list_len)
            yield sig_slot_list

    def _prune_tx_meta_dict(self) -> None:
        for sig_slot in list(self._tx_meta_dict.keys()):
            if sig_slot.block_slot < self._stop_slot:
                self._tx_meta_dict.pop(sig_slot)

    def iter_tx_meta(self, start_slot: int, stop_slot: int) -> Iterator[SolTxMetaInfo]:
        if start_slot < stop_slot:
            return

        is_long_list = (start_slot - stop_slot) > 10
        if is_long_list:
            self._build_checkpoint_list(start_slot)

        self._stop_slot = stop_slot
        for sig_slot_list in self._iter_sig_slot_list(start_slot, is_long_list):
            for tx_meta in self._iter_tx_meta(sig_slot_list):
                self._tx_meta_dict.pop(tx_meta.ident)
                yield tx_meta
