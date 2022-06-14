import bisect
from typing import List, Optional, Tuple

from logged_groups import logged_group

from .mempool_api import MPTxRequest


@logged_group("neon.MemPool")
class MPSenderTxPool:
    def __init__(self, sender_address: str = None):
        self.sender_address = sender_address
        self.txs: List[MPTxRequest] = []
        self._processing_tx: Optional[MPTxRequest] = None

    def __eq__(self, other):
        return self.first_tx_gas_price() == other.first_tx_gas_price()

    def __lt__(self, other):
        return self.first_tx_gas_price() > other.first_tx_gas_price()

    def add_tx(self, mp_tx_request: MPTxRequest):

        index = bisect.bisect_left(self.txs, mp_tx_request)
        if self._processing_tx is not None and mp_tx_request.nonce == self._processing_tx.nonce:
            self.warn(f"Failed to replace processing tx: {self._processing_tx.log_str} with: {mp_tx_request.log_str}")
            return

        found: MPTxRequest = self.txs[index] if index < len(self.txs) else None
        if found is not None and found.nonce == mp_tx_request.nonce:
            self.debug(f"Nonce are equal: {found.nonce}, found: {found.log_str}, new: {mp_tx_request.log_str}")
            if found.gas_price < mp_tx_request.gas_price:
                self.txs[index] = mp_tx_request
            return
        self.txs.insert(index, mp_tx_request)
        self.debug(f"New mp_tx_request: {mp_tx_request.log_str} - inserted at: {index}")

    def get_tx(self):
        return self.txs[0]

    def acquire_tx(self):
        if self.is_processing():
            return None
        self._processing_tx = self.get_tx()
        return self._processing_tx

    def on_processed(self, tx: MPTxRequest):
        assert tx == self._processing_tx, f"tx: {tx.log_str} != processing_tx: {self._processing_tx.log_str}"
        self._processing_tx = None
        self.txs.remove(tx)

    def len(self) -> int:
        return len(self.txs)

    def first_tx_gas_price(self):
        return self.get_tx().gas_price

    def reschedule(self, nonce: int):
        if self._processing_tx is None:
            self.error(f"Failed to finish tx with nonce: {nonce}, processing tx is None")
            return
        if self._processing_tx.nonce != nonce:
            self.error(f"Failed to reschedule, processing tx has different nonce: {self._processing_tx.nonce} than: {nonce}")
            return
        self._processing_tx = None

    def on_tx_done(self, nonce: int):
        if self._processing_tx is None:
            self.error(f"Failed to finish tx with nonce: {nonce}, processing tx is None")
            return
        if self._processing_tx.nonce != nonce:
            self.error(f"Failed to finish tx, processing tx has different nonce: {self._processing_tx.nonce} than: {nonce}")
            return
        self.txs.remove(self._processing_tx)
        self.debug(f"On tx done: {self._processing_tx.log_str} - removed. The: {self.len()} txs are left")
        self._processing_tx = None

    def empty(self) -> bool:
        return len(self.txs) == 0

    def is_processing(self) -> bool:
        return self._processing_tx is not None

    def drop_request_away(self, mp_tx_request: MPTxRequest):
        nonce = mp_tx_request.nonce
        if self._processing_tx is not None and self._processing_tx.nonce == nonce:
            self.warning(f"Failed to drop request away: {mp_tx_request.log_str} - processing")
            return
        index = bisect.bisect_left(self.txs, mp_tx_request)
        if self.txs[index].nonce != nonce:
            self.error(f"Failed to drop reqeust away for: {self.sender_address}, not request with nonce: {nonce}")
            return
        self.debug(f"Remove mp_tx_request from sender: {self.sender_address} - {mp_tx_request.log_str}")
        self.txs = self.txs[index:]


    def drop_last_reqeust(self):
        if len(self.txs) > 0:
            self.erorr("Failed to drop last request from empty sender tx pool")
            return
        self.drop_request_away(self.txs[-1])



@logged_group("neon.MemPool")
class MPTxSchedule:

    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self.sender_tx_pools: List[MPSenderTxPool] = []

    def _pop_sender_txs(self, sender_address: str) -> Optional[MPSenderTxPool]:
        for i, sender_tx_pool in enumerate(self.sender_tx_pools):
            if sender_tx_pool.sender_address != sender_address:
                continue
            return self.sender_tx_pools.pop(i)
        return None

    def _get_sender_txs(self, sender_address: str) -> Tuple[Optional[MPSenderTxPool], int]:
        for i, sender in enumerate(self.sender_tx_pools):
            if sender.sender_address != sender_address:
                continue
            return sender, i
        return None, -1

    def add_mp_tx_request(self, mp_tx_request: MPTxRequest):
        self.debug(f"Add mp_tx_request: {mp_tx_request.log_str}")
        sender_txs = self._pop_sender_or_create(mp_tx_request.sender_address)
        self.debug(f"Got collection for sender: {mp_tx_request.sender_address}, there are already txs: {sender_txs.len()}")
        sender_txs.add_tx(mp_tx_request)
        bisect.insort_left(self.sender_tx_pools, sender_txs)
        self._check_if_overwhelmed()

    def _check_if_overwhelmed(self):
        count = 0
        for sender_txs in self.sender_tx_pools:
            count += sender_txs.len()
        tx_to_remove = count - self._capacity
        sender_to_remove = set()
        for sender in self.sender_tx_pools[-1::-1]:
            if tx_to_remove <= 0:
                break
            sender.drop_last_reqeust()
            tx_to_remove -= 1
            if sender.empty():
                sender_to_remove.add(sender)
        for sender in sender_to_remove:
            self.sender_tx_pools.remove(sender)








    def _pop_sender_or_create(self, sender_address: str) -> MPSenderTxPool:
        sender = self._pop_sender_txs(sender_address)
        return MPSenderTxPool(sender_address=sender_address) if sender is None else sender

    def get_tx_for_execution(self) -> Optional[MPTxRequest]:

        if len(self.sender_tx_pools) == 0:
            return None

        tx: Optional[MPTxRequest] = None
        for sender_txs in self.sender_tx_pools:
            if sender_txs.is_processing():
                continue
            tx = sender_txs.acquire_tx()
            break

        return tx

    def reschedule(self, sender_addr: str, nonce: int):
        sender, _ = self._get_sender_txs(sender_addr)
        if sender is None:
            self.error(f"Failed to reschedule tx, address: {sender_addr}, nonce: {nonce} - sender not found")
        sender.reschedule(nonce)

    def done(self, sender_addr: str, nonce: int):
        sender = self._pop_sender_txs(sender_addr)
        if sender is None:
            self.error(f"Failed to make tx done, address: {sender_addr}, nonce: {nonce} - sender not found")
            return
        sender.on_tx_done(nonce)
        if not sender.empty():
            bisect.insort_left(self.sender_tx_pools, sender)

    def get_pending_trx_count(self, sender_addr: str) -> int:
        sender, _ = self._get_sender_txs(sender_addr)
        return 0 if sender is None else sender.len()

    def drop_reqeust_away(self, mp_tx_reqeust: MPTxRequest):
        sender, i = self._get_sender_txs(mp_tx_reqeust.sender_address)
        if sender is None:
            self.warning(f"Failed drop request, no sender by sender_address: {mp_tx_reqeust.sender_address}")
            return
        sender.drop_request_away(mp_tx_reqeust)
        if sender.len() == 0:
            self.sender_tx_pools.pop(i)
