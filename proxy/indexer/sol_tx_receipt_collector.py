from __future__ import annotations

from multiprocessing.dummy import Pool as ThreadPool

from logged_groups import logged_group
from typing import Optional, Dict, Union, NamedTuple, Iterator, List

from .solana_signatures_db import SolSignsDB, SolTxSignSlotInfo
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.environment_data import INDEXER_PARALLEL_REQUEST_COUNT, INDEXER_POLL_COUNT
from ..common_neon.environment_data import FINALIZED, CONFIRMED


class SolTxReceiptInfo(NamedTuple):
    sign: str
    slot: int
    tx: Dict

    @staticmethod
    def from_response(sign: str, response: Dict) -> SolTxReceiptInfo:
        slot = response['slot']
        return SolTxReceiptInfo(slot=slot, sign=sign, tx=response)


@logged_group("neon.Indexer")
class BaseSolTxReceiptCollector:
    def __init__(self, solana: SolanaInteractor, commitment: str):
        self._solana = solana
        self._commitment = commitment
        self._tx_receipt_dict: Dict[str, Dict] = {}
        self._thread_pool = ThreadPool(INDEXER_PARALLEL_REQUEST_COUNT)

    def _iter_tx_receipt(self, sign_list: List[str]) -> Iterator[SolTxReceiptInfo]:
        group_len = 20
        flat_len = len(sign_list)
        grouped_sign_list = [sign_list[i:(i + group_len)] for i in range(0, flat_len, group_len)]
        self._gather_tx_receipt_dict(grouped_sign_list)
        for sign in reversed(sign_list):
            response = self._tx_receipt_dict.get(sign)
            if response:
                yield SolTxReceiptInfo.from_response(sign, response)

    def _gather_tx_receipt_dict(self, grouped_sign_list: List[List[str]]) -> None:
        self._tx_receipt_dict.clear()
        if len(grouped_sign_list) > 1:
            self._thread_pool.map(self._request_tx_receipt_list, grouped_sign_list)
        elif len(grouped_sign_list) > 0:
            self._request_tx_receipt_list(grouped_sign_list[0])

    def _request_tx_receipt_list(self, sign_list: List[str]) -> None:
        receipt_list = self._solana.get_multiple_receipts(sign_list, commitment=self._commitment)
        for sign, tx in zip(sign_list, receipt_list):
            if tx is not None:
                self._tx_receipt_dict[sign] = tx
                self.debug(f'tx {tx["slot"], sign} is found')
            else:
                self.debug(f'tx {"?", sign} is NOT found')

    def _iter_tx_sign(self, start_sign: Optional[str], start_slot: int, stop_slot: int) -> Iterator[SolTxSignSlotInfo]:
        response_list_len = 1
        while response_list_len:
            response_list = self._request_sign_info_list(start_sign, INDEXER_POLL_COUNT)
            response_list_len = len(response_list)
            if not response_list_len:
                continue
            start_sign = response_list[-1]["signature"]

            for response in response_list:
                slot = response['slot']
                if slot > start_slot:
                    continue
                elif slot < stop_slot:
                    return

                yield SolTxSignSlotInfo(slot=slot, sign=response['signature'])

    def _request_sign_info_list(self, start_sign: Optional[str], limit: int) -> List[Dict[str, Union[int, str]]]:
        response = self._solana.get_signatures_for_address(start_sign, limit, self._commitment)
        error = response.get('error')
        if error:
            self.warning(f'Fail to get signatures: {error}')

        return response.get('result', [])


@logged_group("neon.Indexer")
class FinalizedSolTxReceiptCollector(BaseSolTxReceiptCollector):
    def __init__(self, stop_slot: int, solana: SolanaInteractor):
        super().__init__(solana, commitment=FINALIZED)
        self._signs_db = SolSignsDB()
        self._prev_start_slot = 0
        self._stop_slot = stop_slot
        self._sign_cnt = 0
        self._last_info: Optional[SolTxReceiptInfo] = None

    def get_last_slot(self) -> int:
        return self._stop_slot

    def _build_checkpoint_list(self, start_slot: int) -> None:
        max_sign = self._signs_db.get_max_sign()
        stop_slot = self._stop_slot = max(max_sign.slot, self._stop_slot) if max_sign else self._stop_slot

        for info in self._iter_tx_sign(None, start_slot, stop_slot):
            self._save_checkpoint(info)
        self._reset_checkpoint_cache()

    def _save_checkpoint(self, info: SolTxSignSlotInfo, cnt: int = 1) -> None:
        self._sign_cnt += cnt
        if self._sign_cnt < INDEXER_POLL_COUNT:
            return
        elif self._last_info is None:
            self._last_info = info
        elif self._last_info.slot != info.slot:
            self.debug(f'Save checkpoint: {info.slot, info.sign}')
            self._signs_db.add_sign(info)
            self._reset_checkpoint_cache()

    def _reset_checkpoint_cache(self) -> None:
        self._last_info = None
        self._sign_cnt = 0

    def _iter_tx_sign_list(self, start_slot: int, is_long_list: bool) -> Iterator[List[str]]:
        start_sign: Optional[str] = ''
        next_info: Optional[SolTxSignSlotInfo] = None
        while start_sign is not None:
            if is_long_list:
                next_info = self._signs_db.get_next_sign(self._stop_slot)
            start_sign = next_info.sign if (next_info is not None) else None

            sign_iter = self._iter_tx_sign(start_sign, start_slot, self._stop_slot)
            top_info = next(sign_iter, None)
            if top_info is None:
                return
            self._stop_slot = top_info.slot + 1

            sign_list = [top_info.sign] + [info.sign for info in sign_iter]
            sign_list_len = len(sign_list)
            self._save_checkpoint(top_info, sign_list_len)
            yield sign_list

    def iter_tx_receipt(self, start_slot: int) -> Iterator[SolTxReceiptInfo]:
        if (start_slot < self._stop_slot) or (start_slot <= self._prev_start_slot):
            return
        self._prev_start_slot = start_slot

        is_long_list = (start_slot - self._stop_slot) > 3
        if is_long_list:
            self._build_checkpoint_list(start_slot)

        for sign_list in self._iter_tx_sign_list(start_slot, is_long_list):
            for receipt in self._iter_tx_receipt(sign_list):
                yield receipt


@logged_group("neon.Indexer")
class ConfirmedSolTxReceiptCollector(BaseSolTxReceiptCollector):
    def __init__(self, solana: SolanaInteractor):
        super().__init__(solana, commitment=CONFIRMED)
        self._prev_start_slot = 0

    def iter_tx_receipt(self, start_slot: int, stop_slot: int) -> Iterator[SolTxReceiptInfo]:
        if (start_slot < stop_slot) or (start_slot == self._prev_start_slot):
            return
        self._prev_start_slot = start_slot

        sign_list = [info.sign for info in self._iter_tx_sign(None, start_slot, stop_slot)]
        for receipt in self._iter_tx_receipt(sign_list):
            yield receipt
