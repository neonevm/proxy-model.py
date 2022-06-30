from __future__ import annotations

from multiprocessing.dummy import Pool as ThreadPool

from logged_groups import logged_group
from typing import Optional, Dict, Union, Iterator, List, Any
from abc import ABC, abstractmethod

from .solana_signatures_db import SolSignsDB
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.environment_data import INDEXER_PARALLEL_REQUEST_COUNT, INDEXER_POLL_COUNT
from ..common_neon.environment_data import FINALIZED, CONFIRMED
from ..common_neon.solana_neon_tx_receipt import SolTxMetaInfo, SolTxSignSlotInfo


@logged_group("neon.Indexer")
class SolTxMetaCollector(ABC):
    def __init__(self, solana: SolanaInteractor, commitment: str):
        self._solana = solana
        self._commitment = commitment
        self._is_finalized = (commitment == FINALIZED)
        self._tx_meta_dict: Dict[SolTxSignSlotInfo, Dict[str, Any]] = {}
        self._thread_pool = ThreadPool(INDEXER_PARALLEL_REQUEST_COUNT)

    @property
    def commitment(self) -> str:
        return self._commitment

    @property
    def is_finalized(self) -> bool:
        return self._is_finalized

    @property
    @abstractmethod
    def last_block_slot(self) -> int:
        pass

    @abstractmethod
    def iter_tx_meta(self, start_slot: int, stop_slot: int) -> Iterator[SolTxMetaInfo]:
        pass

    def _iter_tx_meta(self, sign_slot_list: List[SolTxSignSlotInfo]) -> Iterator[SolTxMetaInfo]:
        group_len = 20
        flat_len = len(sign_slot_list)
        grouped_sign_slot_list = [sign_slot_list[i:(i + group_len)] for i in range(0, flat_len, group_len)]
        self._gather_tx_meta_dict(grouped_sign_slot_list)
        for sign_slot in reversed(sign_slot_list):
            response = self._tx_meta_dict.get(sign_slot)
            if response:
                yield SolTxMetaInfo.from_response(sign_slot, response)

    def _gather_tx_meta_dict(self, grouped_sign_slot_list: List[List[SolTxSignSlotInfo]]) -> None:
        if len(grouped_sign_slot_list) > 1:
            self._thread_pool.map(self._request_tx_meta_list, grouped_sign_slot_list)
        elif len(grouped_sign_slot_list) > 0:
            self._request_tx_meta_list(grouped_sign_slot_list[0])

    def _request_tx_meta_list(self, sign_slot_list: List[SolTxSignSlotInfo]) -> None:
        sign_list = [sign_slot.sol_sign for sign_slot in sign_slot_list if sign_slot not in self._tx_meta_dict]
        if not len(sign_list):
            return

        meta_list = self._solana.get_multiple_receipts(sign_list, commitment=self._commitment)
        for sign_slot, tx in zip(sign_slot_list, meta_list):
            if tx is not None:
                self._tx_meta_dict[sign_slot] = tx
                self.debug(f'tx {sign_slot.block_slot}:{sign_slot.sol_sign} is found')
            else:
                self.debug(f'tx {sign_slot.block_slot}:{sign_slot.sol_sign} is NOT found')

    def _iter_sign_slot(self, start_sign: Optional[str], start_slot: int, stop_slot: int) -> Iterator[SolTxSignSlotInfo]:
        response_list_len = 1
        while response_list_len:
            response_list = self._request_sign_info_list(start_sign, INDEXER_POLL_COUNT)
            response_list_len = len(response_list)
            if not response_list_len:
                continue
            start_sign = response_list[-1]["signature"]

            for response in response_list:
                block_slot = response['slot']
                if block_slot > start_slot:
                    continue
                elif block_slot < stop_slot:
                    return

                yield SolTxSignSlotInfo(block_slot=block_slot, sol_sign=response['signature'])

    def _request_sign_info_list(self, start_sign: Optional[str], limit: int) -> List[Dict[str, Union[int, str]]]:
        response = self._solana.get_signatures_for_address(start_sign, limit, self._commitment)
        error = response.get('error')
        if error:
            self.warning(f'Fail to get solana signatures: {error}')

        return response.get('result', [])


@logged_group("neon.Indexer")
class FinalizedSolTxMetaCollector(SolTxMetaCollector):
    def __init__(self, stop_slot: int, solana: SolanaInteractor):
        super().__init__(solana, commitment=FINALIZED)
        self.debug(f'Finalized commitment: {self._commitment}')
        self._signs_db = SolSignsDB()
        self._prev_start_slot = 0
        self._stop_slot = stop_slot
        self._sign_cnt = 0
        self._last_info: Optional[SolTxMetaInfo] = None

    @property
    def last_block_slot(self) -> int:
        return self._stop_slot

    def _build_checkpoint_list(self, start_slot: int) -> None:
        max_sign = self._signs_db.get_max_sign()
        stop_slot = self._stop_slot = max(max_sign.block_slot, self._stop_slot) if max_sign else self._stop_slot

        for info in self._iter_sign_slot(None, start_slot, stop_slot):
            self._save_checkpoint(info)
        self._reset_checkpoint_cache()

    def _save_checkpoint(self, info: SolTxSignSlotInfo, cnt: int = 1) -> None:
        self._sign_cnt += cnt
        if self._sign_cnt < INDEXER_POLL_COUNT:
            return
        elif self._last_info is None:
            self._last_info = info
        elif self._last_info.block_slot != info.block_slot:
            self.debug(f'Save checkpoint: {info.block_slot, info.sol_sign}')
            self._signs_db.add_sign(info)
            self._reset_checkpoint_cache()

    def _reset_checkpoint_cache(self) -> None:
        self._last_info = None
        self._sign_cnt = 0

    def _iter_sign_slot_list(self, start_slot: int, is_long_list: bool) -> Iterator[List[str]]:
        start_sign: Optional[str] = ''
        next_info: Optional[SolTxSignSlotInfo] = None
        while start_sign is not None:
            if is_long_list:
                next_info = self._signs_db.get_next_sign(self._stop_slot)
            start_sign = next_info.sol_sign if (next_info is not None) else None

            sign_slot_list = list(self._iter_sign_slot(start_sign, start_slot, self._stop_slot))
            sign_slot_list_len = len(sign_slot_list)
            if not sign_slot_list_len:
                return
            self._stop_slot = sign_slot_list[0].block_slot + 1

            self._save_checkpoint(sign_slot_list[0], sign_slot_list_len)
            yield sign_slot_list

    def iter_tx_meta(self, start_slot: int, stop_slot: int) -> Iterator[SolTxMetaInfo]:
        if (start_slot < stop_slot) or (start_slot <= self._prev_start_slot):
            return

        if self._stop_slot != stop_slot:
            self._reset_checkpoint_cache()
            self._stop_slot = stop_slot

        self._prev_start_slot = start_slot

        is_long_list = (start_slot - self._stop_slot) > 3
        if is_long_list:
            self._build_checkpoint_list(start_slot)

        for sign_slot_list in self._iter_sign_slot_list(start_slot, is_long_list):
            self._tx_meta_dict.clear()
            for meta in self._iter_tx_meta(sign_slot_list):
                yield meta


@logged_group("neon.Indexer")
class ConfirmedSolTxMetaCollector(SolTxMetaCollector):
    def __init__(self, solana: SolanaInteractor):
        super().__init__(solana, commitment=CONFIRMED)
        self.debug(f'Confirmed commitment: {self._commitment}')
        self._prev_start_slot = 0
        self._last_slot = 0

    @property
    def last_block_slot(self) -> int:
        return self._last_slot

    def iter_tx_meta(self, start_slot: int, stop_slot: int) -> Iterator[SolTxMetaInfo]:
        if (start_slot < stop_slot) or (start_slot == self._prev_start_slot):
            return
        self._prev_start_slot = start_slot

        for sign_slot in list(self._tx_meta_dict.keys()):
            if (sign_slot.block_slot > start_slot) or (sign_slot.block_slot < stop_slot):
                del self._tx_meta_dict[sign_slot]

        sign_slot_list = list(self._iter_sign_slot(None, start_slot, stop_slot))
        for meta in self._iter_tx_meta(sign_slot_list):
            self._last_slot = meta.block_slot
            yield meta
