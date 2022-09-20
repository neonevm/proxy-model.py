import multiprocessing as mp
import ctypes
import pickle

from dataclasses import dataclass
from typing import List

from ..common_neon.solana_transaction import SolLegacyTx, SolPubKey
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.neon_instruction import NeonIxBuilder


@dataclass
class ALTCloseInfo:
    close_block_height: int
    table_account: str
    signer_key: str


# TODO: Should be optimized for big number of ALT
# TODO: Add initialization on startup
class ALTCloseQueue:
    CLOSE_BLOCK_HEIGHT_CNT = 512 + 12
    """The close-time is equivalent to the amount of time it takes for a slot to be removed from the slot hash list."""

    _manager = mp.Manager()
    _queue_value = mp.Value(ctypes.c_ulonglong, 0)
    _queue = _manager.list()

    def __init__(self, solana: SolInteractor):
        self._solana = solana

    def _get_block_height(self) -> int:
        return self._solana.get_block_height('finalized')

    def push_list(self, signer_key: SolPubKey, table_account_list: List[SolPubKey]) -> None:
        block_height = self._get_block_height()
        close_block_height = block_height + self.CLOSE_BLOCK_HEIGHT_CNT

        new_queue: List[bytes] = []
        for table_acct in table_account_list:
            data = pickle.dumps(ALTCloseInfo(
                close_block_height=close_block_height,
                table_account=str(table_acct),
                signer_key=str(signer_key)
            ))
            new_queue.append(data)

        with self._queue_value.get_lock():
            self._queue.extend(new_queue)

    def _pop_acct_list(self, signer_key: SolPubKey) -> List[SolPubKey]:
        block_height = self._get_block_height()
        signer_key = str(signer_key)

        stop_pos = 0
        table_acct_list: List[SolPubKey] = []
        new_queue: List[bytes] = []
        with self._queue_value.get_lock():
            for data in self._queue:
                alt_close_info = pickle.loads(data)
                if alt_close_info.close_block_height > block_height:
                    if stop_pos > 0:
                        new_queue.extend(self._queue[stop_pos:])
                    break

                stop_pos += 1
                if alt_close_info.signer_key != signer_key:
                    new_queue.append(data)
                    continue

                table_acct_list.append(SolPubKey(alt_close_info.table_account))

            if stop_pos > 0:
                del self._queue[:]
                self._queue.extend(new_queue)

        return table_acct_list

    def pop_tx_list(self, signer_key: SolPubKey) -> List[SolLegacyTx]:
        tx_list: List[SolLegacyTx] = []
        table_acct_list = self._pop_acct_list(signer_key)
        if not len(table_acct_list):
            return tx_list

        builder = NeonIxBuilder(signer_key)
        for table_acct in table_acct_list:
            tx_list.append(SolLegacyTx().add(builder.make_close_lookup_table_ix(table_acct)))
        return tx_list
