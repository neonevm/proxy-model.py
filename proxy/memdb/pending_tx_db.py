import multiprocessing as mp
import ctypes
import pickle
from typing import Optional

from logged_groups import logged_group

from ..indexer.indexer_db import IndexerDB
from ..common_neon.errors import PendingTxError
from ..common_neon.eth_proto import Trx as EthTx
from ..common_neon.utils.utils import NeonTxInfo


class NeonPendingTxInfo:
    def __init__(self, neon_tx: EthTx, neon_sig: str, operator: str, block_slot: int):
        self.neon_tx = NeonTxInfo(tx=neon_tx)
        self.neon_sig = neon_sig
        self.operator = operator
        self.block_slot = block_slot

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, src):
        self.__dict__ = src


@logged_group("neon.Proxy")
class MemPendingTxsDB:
    # These variables are global for class, they will be initialized one time
    BIG_SLOT = 1_000_000_000_000

    _manager = mp.Manager()

    _pending_slot = mp.Value(ctypes.c_ulonglong, BIG_SLOT)

    _pending_tx_by_hash = _manager.dict()
    _pending_slot_by_hash = _manager.dict()

    def __init__(self, db: IndexerDB):
        self._db = db

    def _set_tx(self, tx: NeonPendingTxInfo):
        data = pickle.dumps(tx)
        self._pending_tx_by_hash[tx.neon_sig] = data
        self._pending_slot_by_hash[tx.neon_sig] = tx.block_slot

        if self._pending_slot.value > tx.block_slot:
            self._pending_slot.value = tx.block_slot

    def _rm_finalized_txs(self, finalized_block_slot: int):
        if self._pending_slot.value > finalized_block_slot:
            return

        rm_sig_list = []
        pending_slot = self.BIG_SLOT

        # Filter tx by slot
        for sig, slot in self._pending_slot_by_hash.items():
            if slot < finalized_block_slot:
                rm_sig_list.append(sig)
            elif pending_slot > slot:
                pending_slot = slot

        self._pending_slot.value = pending_slot

        # Remove old txs
        for sig in rm_sig_list:
            del self._pending_tx_by_hash[sig]
            del self._pending_slot_by_hash[sig]

    def pend_transaction(self, tx: NeonPendingTxInfo):
        finalized_block_slot = self._db.get_finalized_block_slot()

        executed_tx = self._db.get_tx_by_neon_sig(tx.neon_sig)
        if executed_tx:
            raise PendingTxError(f'Transaction {tx.neon_sig} is already executed')

        with self._pending_slot.get_lock():
            self._rm_finalized_txs(finalized_block_slot)

            pended_data = self._pending_tx_by_hash.get(tx.neon_sig)
            if not pended_data:
                return self._set_tx(tx)

            pended_operator = pickle.loads(pended_data).operator
            if pended_operator == tx.operator:
                self._set_tx(tx)
            else:
                raise PendingTxError(f'Transaction {tx.neon_sig} is locked ' +
                                     f'by other operator resource {pended_operator}')

    def get_tx_by_neon_sig(self, neon_sig: str) -> Optional[NeonPendingTxInfo]:
        with self._pending_slot.get_lock():
            encoded_data = self._pending_tx_by_hash.get(neon_sig)
            if not encoded_data:
                return None
            return pickle.loads(encoded_data)
