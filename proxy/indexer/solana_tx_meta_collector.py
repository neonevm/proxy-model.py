from __future__ import annotations

from multiprocessing.dummy import Pool as ThreadPool

from logged_groups import logged_group
from typing import Optional, Dict, Union, Iterator, List, Any
from abc import ABC, abstractmethod

from .solana_signatures_db import SolSignsDB, SolTxSignSlotInfo
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.environment_data import INDEXER_PARALLEL_REQUEST_COUNT, INDEXER_POLL_COUNT
from ..common_neon.environment_data import FINALIZED, CONFIRMED
from ..common_neon.solana_neon_tx_receipt import SolTxMetaInfo


@logged_group("neon.Indexer")
class SolTxMetaCollector(ABC):
    def __init__(self, solana: SolanaInteractor, commitment: str):
        self._solana = solana
        self._commitment = commitment
        self._tx_meta_dict: Dict[str, Dict[str, Any]] = {}
        self._thread_pool = ThreadPool(INDEXER_PARALLEL_REQUEST_COUNT)

    @property
    def commitment(self) -> str:
        return self._commitment

    @property
    @abstractmethod
    def last_block_slot(self) -> int:
        pass

    @abstractmethod
    def iter_tx_meta(self, start_slot: int, stop_slot: int) -> Iterator[SolTxMetaInfo]:
        pass

    def _iter_tx_meta(self, sol_sign_list: List[str]) -> Iterator[SolTxMetaInfo]:
        group_len = 20
        flat_len = len(sol_sign_list)
        grouped_sol_sign_list = [sol_sign_list[i:(i + group_len)] for i in range(0, flat_len, group_len)]
        self._gather_tx_meta_dict(grouped_sol_sign_list)
        for sol_sign in reversed(sol_sign_list):
            response = self._tx_meta_dict.get(sol_sign)
            if response:
                yield SolTxMetaInfo.from_response(sol_sign, response)

    def _gather_tx_meta_dict(self, grouped_sol_sign_list: List[List[str]]) -> None:
        self._tx_meta_dict.clear()
        if len(grouped_sol_sign_list) > 1:
            self._thread_pool.map(self._request_tx_meta_list, grouped_sol_sign_list)
        elif len(grouped_sol_sign_list) > 0:
            self._request_tx_meta_list(grouped_sol_sign_list[0])

    def _request_tx_meta_list(self, sol_sign_list: List[str]) -> None:
        meta_list = self._solana.get_multiple_receipts(sol_sign_list, commitment=self._commitment)
        for sol_sign, tx in zip(sol_sign_list, meta_list):
            if tx is not None:
                self._tx_meta_dict[sol_sign] = tx
                self.debug(f'tx {tx["slot"], sol_sign} is found')
            else:
                self.debug(f'tx {"?", sol_sign} is NOT found')

    def _iter_tx_sol_sign(self, start_sol_sign: Optional[str], start_slot: int, stop_slot: int) -> Iterator[SolTxSignSlotInfo]:
        response_list_len = 1
        while response_list_len:
            response_list = self._request_sol_sign_info_list(start_sol_sign, INDEXER_POLL_COUNT)
            response_list_len = len(response_list)
            if not response_list_len:
                continue
            start_sol_sign = response_list[-1]["signature"]

            for response in response_list:
                block_slot = response['slot']
                if block_slot > start_slot:
                    continue
                elif block_slot < stop_slot:
                    return

                yield SolTxSignSlotInfo(block_slot=block_slot, sol_sign=response['signature'])

    def _request_sol_sign_info_list(self, start_sol_sign: Optional[str], limit: int) -> List[Dict[str, Union[int, str]]]:
        response = self._solana.get_signatures_for_address(start_sol_sign, limit, self._commitment)
        error = response.get('error')
        if error:
            self.warning(f'Fail to get sol_signatures: {error}')

        return response.get('result', [])


@logged_group("neon.Indexer")
class FinalizedSolTxMetaCollector(SolTxMetaCollector):
    def __init__(self, stop_slot: int, solana: SolanaInteractor):
        super().__init__(solana, commitment=FINALIZED)
        self._sol_signs_db = SolSignsDB()
        self._prev_start_slot = 0
        self._stop_slot = stop_slot
        self._sol_sign_cnt = 0
        self._last_info: Optional[SolTxMetaInfo] = None

    @property
    def last_block_slot(self) -> int:
        return self._stop_slot

    def _build_checkpoint_list(self, start_slot: int) -> None:
        max_sol_sign = self._sol_signs_db.get_max_sign()
        stop_slot = self._stop_slot = max(max_sol_sign.block_slot, self._stop_slot) if max_sol_sign else self._stop_slot

        for info in self._iter_tx_sol_sign(None, start_slot, stop_slot):
            self._save_checkpoint(info)
        self._reset_checkpoint_cache()

    def _save_checkpoint(self, info: SolTxSignSlotInfo, cnt: int = 1) -> None:
        self._sol_sign_cnt += cnt
        if self._sol_sign_cnt < INDEXER_POLL_COUNT:
            return
        elif self._last_info is None:
            self._last_info = info
        elif self._last_info.block_slot != info.block_slot:
            self.debug(f'Save checkpoint: {info.block_slot, info.sol_sign}')
            self._sol_signs_db.add_sign(info)
            self._reset_checkpoint_cache()

    def _reset_checkpoint_cache(self) -> None:
        self._last_info = None
        self._sol_sign_cnt = 0

    def _iter_tx_sol_sign_list(self, start_slot: int, is_long_list: bool) -> Iterator[List[str]]:
        start_sol_sign: Optional[str] = ''
        next_info: Optional[SolTxSignSlotInfo] = None
        while start_sol_sign is not None:
            if is_long_list:
                next_info = self._sol_signs_db.get_next_sign(self._stop_slot)
            start_sol_sign = next_info.sol_sign if (next_info is not None) else None

            sol_sign_iter = self._iter_tx_sol_sign(start_sol_sign, start_slot, self._stop_slot)
            top_info = next(sol_sign_iter, None)
            if top_info is None:
                return
            self._stop_slot = top_info.block_slot + 1

            sol_sign_list = [top_info.sol_sign] + [info.sol_sign for info in sol_sign_iter]
            sol_sign_list_len = len(sol_sign_list)
            self._save_checkpoint(top_info, sol_sign_list_len)
            yield sol_sign_list

    def iter_tx_meta(self, start_slot: int, stop_slot: int) -> Iterator[SolTxMetaInfo]:
        if (start_slot < stop_slot) or (start_slot <= self._prev_start_slot):
            return
        self._stop_slot = stop_slot
        self._prev_start_slot = start_slot

        is_long_list = (start_slot - self._stop_slot) > 3
        if is_long_list:
            self._build_checkpoint_list(start_slot)

        for sol_sign_list in self._iter_tx_sol_sign_list(start_slot, is_long_list):
            for meta in self._iter_tx_meta(sol_sign_list):
                yield meta


@logged_group("neon.Indexer")
class ConfirmedSolTxMetaCollector(SolTxMetaCollector):
    def __init__(self, solana: SolanaInteractor):
        super().__init__(solana, commitment=CONFIRMED)
        self._prev_start_slot = 0
        self._last_slot = 0

    @property
    def last_block_slot(self) -> int:
        return self._last_slot

    def iter_tx_meta(self, start_slot: int, stop_slot: int) -> Iterator[SolTxMetaInfo]:
        if (start_slot < stop_slot) or (start_slot == self._prev_start_slot):
            return
        self._prev_start_slot = start_slot

        sol_sign_list = [info.sol_sign for info in self._iter_tx_sol_sign(None, start_slot, stop_slot)]
        for meta in self._iter_tx_meta(sol_sign_list):
            self._last_slot = meta.block_slot
            yield meta
