import multiprocessing
import ctypes
import pickle

from logged_groups import logged_group

from ..indexer.indexer_db import IndexerDB


class PendingTxError(Exception):
    def __init__(self, err):
        super().__init__(err)


class NeonPendingTxInfo:
    def __init__(self, neon_sign: str, operator: str, slot: int):
        self.neon_sign = neon_sign
        self.operator = operator
        self.slot = slot

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, src):
        self.__dict__ = src


@logged_group("neon.Proxy")
class PendingTxsDB:
    # These variables are global for class, they will be initialized one time
    _manager = multiprocessing.Manager()

    _pending_tx_lock = _manager.Lock()
    _pending_slot = _manager.Value(ctypes.c_ulonglong, 0)
    _pending_tx_by_hash = _manager.dict()

    def __init__(self, db: IndexerDB):
        self._db = db

    def _set_tx(self, tx: NeonPendingTxInfo):
        data = pickle.dumps(tx)
        self._pending_tx_by_hash.setdefault(tx.neon_sign, data)

        if (self._pending_slot.value == 0) or (self._pending_slot.value > tx.slot):
            self._pending_slot.value = tx.slot

    def _rm_finalized_txs(self, before_slot: int):
        if (self._pending_slot.value == 0) or (self._pending_slot.value > before_slot):
            return

        rm_sign_list = []
        self._pending_slot.value = 0

        # Filter tx by slot
        for data in self._pending_tx_by_hash.values():
            tx = pickle.loads(data)
            if tx.slot < before_slot:
                rm_sign_list.append(tx.neon_sign)
            elif (self._pending_slot.value == 0) or (self._pending_slot.value > tx.slot):
                self._pending_slot.value = tx.slot

        # Remove old txs
        for sign in rm_sign_list:
            del self._pending_tx_by_hash[sign]

    def pend_transaction(self, tx: NeonPendingTxInfo, before_slot: int):
        executed_tx = self._db.get_tx_by_neon_sign(tx.neon_sign)
        if executed_tx:
            raise PendingTxError(f'Transaction {tx.neon_sign} is already executed')

        with self._pending_tx_lock:
            self._rm_finalized_txs(before_slot)

            pended_data = self._pending_tx_by_hash.get(tx.neon_sign)
            if not pended_data:
                self._set_tx(tx)
            elif pickle.loads(pended_data).operator == tx.operator:
                self._set_tx(tx)
            else:
                raise PendingTxError(f'Transaction {tx.neon_sign} is locked in other worker')
