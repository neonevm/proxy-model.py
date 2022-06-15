import bisect
from typing import List, Optional, Tuple

from logged_groups import logged_group

from .mempool_api import MPTxRequest


@logged_group("neon.MemPool")
class MPSenderTxPool:
    def __init__(self, sender_address: str = None):
        self._sender_address = sender_address
        self._txs: List[MPTxRequest] = []
        self._processing_tx: Optional[MPTxRequest] = None

    def __eq__(self, other):
        return self.first_tx_gas_price() == other.first_tx_gas_price()

    def __lt__(self, other):
        return self.first_tx_gas_price() > other.first_tx_gas_price()

    def add_tx(self, mp_tx_request: MPTxRequest):

        index = bisect.bisect_left(self._txs, mp_tx_request)
        if self._processing_tx is not None and mp_tx_request.nonce == self._processing_tx.nonce:
            self.warn(f"Failed to replace processing tx: {self._processing_tx.log_str} with: {mp_tx_request.log_str}")
            return

        found: MPTxRequest = self._txs[index] if index < len(self._txs) else None
        if found is not None and found.nonce == mp_tx_request.nonce:
            self.debug(f"Nonce are equal: {found.nonce}, found: {found.log_str}, new: {mp_tx_request.log_str}")
            if found.gas_price < mp_tx_request.gas_price:
                self._txs[index] = mp_tx_request
            return
        self._txs.insert(index, mp_tx_request)
        self.debug(f"New mp_tx_request: {mp_tx_request.log_str} - inserted at: {index}")

    def get_tx(self):
        return None if self.is_empty() else self._txs[0]

    def acquire_tx(self):
        if self.is_processing():
            return None
        self._processing_tx = self.get_tx()
        return self._processing_tx

    def on_processed(self, tx: MPTxRequest):
        assert tx == self._processing_tx, f"tx: {tx.log_str} != processing_tx: {self._processing_tx.log_str}"
        self._processing_tx = None
        self._txs.remove(tx)

    def len(self) -> int:
        return len(self._txs)

    def first_tx_gas_price(self):
        tx = self.get_tx()
        return tx.gas_price if tx is not None else 0

    def on_tx_done(self, nonce: int):
        if self._processing_tx is None:
            self.error(f"Failed to finish tx with nonce: {nonce}, processing tx is None")
            return
        if self._processing_tx.nonce != nonce:
            self.error(f"Failed to finish tx, processing tx has different nonce: {self._processing_tx.nonce} than: {nonce}")
            return
        self._txs.remove(self._processing_tx)
        self.debug(f"On tx done: {self._processing_tx.log_str} - removed. The: {self.len()} txs are left")
        self._processing_tx = None

    def is_empty(self) -> bool:
        return self.len() == 0

    def is_processing(self) -> bool:
        return self._processing_tx is not None

    def drop_last_request(self):
        if self.is_empty():
            self.erorr("Failed to drop last request from empty sender tx pool")
            return
        if self._processing_tx is self._txs[-1]:
            self.warning(f"Failed to drop last request away: {self._processing_tx.log_str} - processing")
            return
        self.debug(f"Remove last mp_tx_request from sender: {self._sender_address} - {self._txs[-1].log_str}")
        self._txs = self._txs[:-1]


@logged_group("neon.MemPool")
class MPTxSchedule:

    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._sender_tx_pools: List[MPSenderTxPool] = []

    def _pop_sender_txs(self, sender_address: str) -> Optional[MPSenderTxPool]:
        for i, sender_tx_pool in enumerate(self._sender_tx_pools):
            if sender_tx_pool._sender_address != sender_address:
                continue
            return self._sender_tx_pools.pop(i)
        return None

    def _get_sender_txs(self, sender_address: str) -> Tuple[Optional[MPSenderTxPool], int]:
        for i, sender in enumerate(self._sender_tx_pools):
            if sender._sender_address != sender_address:
                continue
            return sender, i
        return None, -1

    def add_mp_tx_request(self, mp_tx_request: MPTxRequest):
        self.debug(f"Add mp_tx_request: {mp_tx_request.log_str}")
        sender_txs = self._pop_sender_or_create(mp_tx_request.sender_address)
        self.debug(f"Got collection for sender: {mp_tx_request.sender_address}, there are already txs: {sender_txs.len()}")
        sender_txs.add_tx(mp_tx_request)
        bisect.insort_left(self._sender_tx_pools, sender_txs)

        self._check_oversized_and_reduce()

    def get_mp_tx_count(self):
        count = 0
        for sender_txs in self._sender_tx_pools:
            count += sender_txs.len()
        return count

    def _check_oversized_and_reduce(self):
        count = self.get_mp_tx_count()
        tx_to_remove = count - self._capacity
        sender_to_remove = []
        for sender in self._sender_tx_pools[::-1]:
            if tx_to_remove <= 0:
                break
            sender.drop_last_request()
            tx_to_remove -= 1
            if sender.len() == 1 and sender.is_processing():
                continue
            if sender.is_empty():
                sender_to_remove.append(sender)
        for sender in sender_to_remove:
            self._sender_tx_pools.remove(sender)

    def _pop_sender_or_create(self, sender_address: str) -> MPSenderTxPool:
        sender = self._pop_sender_txs(sender_address)
        return MPSenderTxPool(sender_address=sender_address) if sender is None else sender

    def acquire_tx_for_execution(self) -> Optional[MPTxRequest]:

        if len(self._sender_tx_pools) == 0:
            return None

        tx: Optional[MPTxRequest] = None
        for sender_txs in self._sender_tx_pools:
            if sender_txs.is_processing():
                continue
            tx = sender_txs.acquire_tx()
            break

        return tx

    def done(self, sender_addr: str, nonce: int):
        sender = self._pop_sender_txs(sender_addr)
        if sender is None:
            self.error(f"Failed to make tx done, address: {sender_addr}, nonce: {nonce} - sender not found")
            return
        sender.on_tx_done(nonce)
        if not sender.is_empty():
            bisect.insort_left(self._sender_tx_pools, sender)

    def get_pending_trx_count(self, sender_addr: str) -> int:
        sender, _ = self._get_sender_txs(sender_addr)
        return 0 if sender is None else sender.len()
