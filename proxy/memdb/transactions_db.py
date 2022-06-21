import multiprocessing as mp
import pickle
import ctypes

from typing import Optional, List
from logged_groups import logged_group

from ..common_neon.utils import NeonTxInfo, NeonTxResultInfo, NeonTxFullInfo

from ..indexer.indexer_db import IndexerDB


@logged_group("neon.Proxy")
class MemTxsDB:
    BIG_SLOT = 1_000_000_000_000

    _manager = mp.Manager()

    _tx_slot = mp.Value(ctypes.c_ulonglong, BIG_SLOT)

    _tx_by_neon_sign = _manager.dict()
    _slot_by_neon_sign = _manager.dict()

    def __init__(self, db: IndexerDB):
        self._db = db

    def _rm_finalized_txs(self, before_slot: int):
        if self._tx_slot.value > before_slot:
            return

        rm_neon_sign_list = []
        tx_slot = self.BIG_SLOT
        for sign, slot in self._slot_by_neon_sign.items():
            if slot <= before_slot:
                rm_neon_sign_list.append(sign)
            elif tx_slot > slot:
                tx_slot = slot
        self._tx_slot.value = tx_slot

        for neon_sign in rm_neon_sign_list:
            del self._tx_by_neon_sign[neon_sign]
            del self._slot_by_neon_sign[neon_sign]

    def get_tx_by_neon_sign(self, neon_sign: str, is_pended_tx: bool, before_slot: int) -> Optional[NeonTxFullInfo]:
        if not is_pended_tx:
            return self._db.get_tx_by_neon_sign(neon_sign)

        with self._tx_slot.get_lock():
            self._rm_finalized_txs(before_slot)
            data = self._tx_by_neon_sign.get(neon_sign)
            if data:
                return pickle.loads(data)
        return None

    def get_tx_list_by_neon_sign_list(self, neon_sign_list: List[str], before_slot: int) -> List[NeonTxFullInfo]:
        tx_list = []
        with self._tx_slot.get_lock():
            self._rm_finalized_txs(before_slot)
            for neon_sign in neon_sign_list:
                data = self._tx_by_neon_sign.get(neon_sign)
                if data:
                    tx_list.append(pickle.loads(data))
        return tx_list

    def get_logs(self, from_block, to_block, addresses, topics, block_hash):
        def _has_address(src_addresses, dst_address):
            return dst_address in src_addresses

        def _has_topics(src_topics, dst_topics):
            for topic in src_topics:
                if topic in dst_topics:
                    return True
            return False

        result_list = []
        with self._tx_slot.get_lock():
            for data in self._tx_by_neon_sign.values():
                tx = pickle.loads(data)
                if from_block and tx.neon_res.slot < from_block:
                    continue
                if to_block and tx.neon_res.slot > to_block:
                    continue
                if block_hash and tx.neon_res.block_hash != block_hash:
                    continue
                for log in tx.neon_res.logs:
                    if len(addresses) and (not _has_address(addresses, log['address'])):
                        continue
                    if len(topics) and (not _has_topics(topics, log['topics'])):
                        continue
                    result_list.append(log)

        return result_list + self._db.get_logs(from_block, to_block, addresses, topics, block_hash)

    def get_sol_sign_list_by_neon_sign(self, neon_sign: str, is_pended_tx: bool, before_slot: int) -> List[str]:
        if not is_pended_tx:
            return self._db.get_sol_sign_list_by_neon_sign(neon_sign)

        with self._tx_slot.get_lock():
            self._rm_finalized_txs(before_slot)
            data = self._tx_by_neon_sign.get(neon_sign)
            if data:
                return pickle.loads(data).used_ixs
        return []

    def submit_transaction(self, neon_tx: NeonTxInfo, neon_res: NeonTxResultInfo, sign_list: List[str], before_slot: int):
        tx = NeonTxFullInfo(neon_tx=neon_tx, neon_res=neon_res, used_ixs=sign_list)
        data = pickle.dumps(tx)

        with self._tx_slot.get_lock():
            self._rm_finalized_txs(before_slot)

            self._tx_by_neon_sign[tx.neon_tx.sign] = data
            self._slot_by_neon_sign[tx.neon_tx.sign] = tx.neon_res.slot

            if self._tx_slot.value > tx.neon_res.slot:
                self._tx_slot.value = tx.neon_res.slot
