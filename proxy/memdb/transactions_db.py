import multiprocessing
import pickle
import ctypes

from logged_groups import logged_group

from ..common_neon.utils import NeonTxInfo, NeonTxResultInfo, NeonTxFullInfo, SolanaBlockInfo

from ..indexer.indexer_db import IndexerDB


@logged_group("neon.Proxy")
class TxsDB:
    _manager = multiprocessing.Manager()

    _tx_lock = _manager.Lock()
    _tx_slot = _manager.Value(ctypes.c_ulonglong, 0)
    _tx_by_neon_sign = _manager.dict()
    _tx_by_sol_sign = _manager.dict()

    def __init__(self, db: IndexerDB):
        self._db = db

    def _rm_finalized_txs(self, before_slot: int):
        if (self._tx_slot.value == 0) or (self._tx_slot.value > before_slot):
            return

        rm_sol_list = []
        rm_neon_list = []
        self._tx_slot.value = 0
        for data in self._tx_by_neon_sign.values():
            tx = pickle.loads(data)
            if tx.neon_res.slot <= before_slot:
                self.debug(f'remove {tx.neon_tx.sign} ({tx.neon_res.slot} <= {before_slot})')
                rm_neon_list.append(tx.neon_tx.sign)
                rm_sol_list.append(tx.neon_res.sol_sign)
            elif (self._tx_slot.value == 0) or (self._tx_slot.value > tx.neon_res.slot):
                self._tx_slot.value = tx.neon_res.slot

        for sol_sign, neon_sign in zip(rm_sol_list, rm_neon_list):
            del self._tx_by_neon_sign[neon_sign]
            del self._tx_by_sol_sign[sol_sign]

    def get_tx_by_sol_sign(self, sol_sign: str, before_slot: int) -> NeonTxFullInfo:
        with self._tx_lock:
            self._rm_finalized_txs(before_slot)
            data = self._tx_by_sol_sign.get(sol_sign)
            if data:
                return pickle.loads(data)
        return self._db.get_tx_by_sol_sign(sol_sign)

    def get_tx_by_neon_sign(self, neon_sign: str, before_slot: int) -> NeonTxFullInfo:
        with self._tx_lock:
            self._rm_finalized_txs(before_slot)
            data = self._tx_by_neon_sign.get(neon_sign)
            if data:
                return pickle.loads(data)
        return self._db.get_tx_by_neon_sign(neon_sign)

    def get_logs(self, from_block, to_block, addresses, topics, block_hash):
        def _has_address(src_addresses, dst_address):
            return dst_address in src_addresses

        def _has_topics(src_topics, dst_topics):
            for topic in src_topics:
                if topic in dst_topics:
                    return True
            return False

        result_list = []
        with self._tx_lock:
            for data in self._tx_by_neon_sign.values():
                tx = pickle.loads(data)
                if from_block and tx.neon_res.block_height < from_block:
                    continue
                if to_block and tx.neon_res.block_height > to_block:
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

    def submit_transaction(self, neon_tx: NeonTxInfo, neon_res: NeonTxResultInfo, before_slot: int):
        tx = NeonTxFullInfo(neon_tx=neon_tx, neon_res=neon_res)
        data = pickle.dumps(tx)

        with self._tx_lock:
            self._rm_finalized_txs(before_slot)
            self._tx_by_neon_sign[tx.neon_tx.sign] = data
            self._tx_by_sol_sign[tx.neon_res.sol_sign] = data
            if (self._tx_slot.value == 0) or (self._tx_slot.value > tx.neon_res.slot):
                self._tx_slot.value = tx.neon_res.slot
