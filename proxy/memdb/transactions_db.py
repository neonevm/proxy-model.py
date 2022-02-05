import multiprocessing
import pickle

from logged_groups import logged_group

from ..common_neon.utils import NeonTxInfo, NeonTxResultInfo, NeonTxFullInfo, SolanaBlockInfo

from ..indexer.indexer_db import IndexerDB


@logged_group("neon.Proxy")
class TxsDB:
    _manager = multiprocessing.Manager()

    _tx_lock = _manager.Lock()
    _tx_slot = _manager.Value('Q', 0)
    _tx_by_neon_sign = _manager.dict()
    _tx_by_sol_sign = _manager.dict()

    def __init__(self, db: IndexerDB):
        self._db = db

    def _rm_finalized_txs(self, before_slot: int):
        if (not self._tx_slot.value) or (self._tx_slot.value > before_slot):
            return

        rm_sol_list = []
        rm_neon_list = []
        self._tx_slot.value = 0
        for data in self._tx_by_neon_sign.values():
            tx = pickle.loads(data)
            if tx.neon_res.slot <= before_slot:
                rm_neon_list.append(tx.neon_tx.sign)
                rm_sol_list.append(tx.neon_res.sol_sign)
            elif (not self._tx_slot.value) or (self._tx_slot.value > tx.neon_res.slot):
                self._tx_slot.value = tx.neon_res.slot

        for sol_sign, neon_sign in zip(rm_sol_list, rm_neon_list):
            del self._tx_by_neon_sign[neon_sign]
            del self._tx_by_sol_sign[sol_sign]

    def get_tx_by_sol_sign(self, sol_sign: str, before_slot: int) -> NeonTxFullInfo:
        with self._tx_lock:
            self._rm_finalized_txs(0)
            data = self._tx_by_sol_sign.get(sol_sign)
            if data:
                return pickle.loads(data)
        return self._txs_db.get_tx_by_sol_sign(sol_sign, before_slot)

    def get_tx_by_neon_sign(self, neon_sign: str, before_slot: int) -> NeonTxFullInfo:
        with self._tx_lock:
            self._rm_finalized_txs(before_slot)
            data = self._tx_by_sol_sign.get(neon_sign)
            if data:
                return pickle.loads(data)

        return self._txs_db.get_tx_by_neon_sign(neon_sign)

    def get_logs(self, from_block, to_block, addresses, topics, block_hash):
        result_list = []
        with self._tx_lock:
            for data in self._tx_by_neon_sign:
                tx = pickle.load(data)
                if from_block and tx.block.height < from_block:
                    continue
                if to_block and tx.block.height > to_block:
                    continue
                if block_hash and tx.block.hash != block_hash:
                    continue
                for log in tx.neon_res.logs:
                    if len(addresses) and (log.address not in addresses):
                        continue
                    if len(topics) and (log.topic not in topics):
                        continue
                    result_list.append(log)

        return result_list + self._db.get_logs(from_block, to_block, addresses, topics, block_hash)

    def submit_transaction(self, neon_tx: NeonTxInfo, neon_res: NeonTxResultInfo, block: SolanaBlockInfo, before_slot):
        tx = NeonTxFullInfo(neon_tx=neon_tx, neon_res=neon_res, block=block)
        data = pickle.dumps(tx)

        with self._tx_lock:
            self._rm_finalized_txs(before_slot)
            self._tx_by_neon_sign[tx.neon_tx.sign] = data
            self._tx_by_sol_sign[tx.neon_res.sol_sign] = data
            if (not self._tx_slot.value) or (self._tx_slot.value > tx.neon_res.slot):
                self._tx_slot.value = tx.neon_res.slot
