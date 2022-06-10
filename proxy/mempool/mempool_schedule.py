import bisect
from typing import List, Optional

from logged_groups import logged_group

from .mempool_api import MPTxRequest


@logged_group("neon.MemPool")
class MPSenderTXs:
    def __init__(self, sender_address: str = None):
        self.address = sender_address
        self.txs: List[MPTxRequest] = []
        self._processing_tx: Optional[MPTxRequest] = None

    def __eq__(self, other):
        return self.first_tx_gas_price() == other.first_tx_gas_price()

    def __lt__(self, other):
        return self.first_tx_gas_price() > other.first_tx_gas_price()

    def add_tx(self, tx: MPTxRequest):
        index = bisect.bisect_left(self.txs, tx)
        if self._processing_tx is not None and tx.nonce == self._processing_tx.nonce:
            self.warn(f"Failed to replace processing tx: {self._processing_tx.log_str} with: {tx.log_str}")
            return

        found: MPTxRequest = self.txs[index] if index < len(self.txs) else None
        if found is not None and found.nonce == tx.nonce:
            self.debug(f"Nonces are equal: {found.nonce}, found: {found.log_str}, new: {tx.log_str}")
            if found.gas_price < tx.gas_price:
                self.txs[index] = tx
            return
        self.debug(f"Is about to insert tx.Index: {index}, txs len: {len(self.txs)}")
        self.txs.insert(index, tx)
        self.debug(f"New txs: {tx.log_str} inserted at: {index}")

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
            self.error(f"Fauled to reschedule, processing tx has different nonce: {self._processing_tx.nonce} than: {nonce}")
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


@logged_group("neon.MemPool")
class MPTxSchedule:

    def __init__(self) -> None:
        self.senders: List[MPSenderTXs] = []

    def _pop_sender_txs(self, sender_address: str) -> Optional[MPSenderTXs]:
        for i, sender in enumerate(self.senders):
            if sender.address != sender_address:
                continue
            return self.senders.pop(i)
        return None

    def _get_sender_txs(self, sender_address: str) -> Optional[MPSenderTXs]:
        for i, sender in enumerate(self.senders):
            if sender.address != sender_address:
                continue
            return sender
        return None

    def add_tx(self, tx: MPTxRequest):
        self.debug(f"Add tx: ")
        sender = self._pop_sender_or_create(tx.sender_address)
        self.debug(f"Got sender: {sender.address}, txs: {sender.len()}")
        sender.add_tx(tx)
        self.debug(f"Look index for sender: {sender.first_tx_gas_price()} in: {self.senders}")
        bisect.insort_left(self.senders, sender)

    def _pop_sender_or_create(self, sender_address: str) -> MPSenderTXs:
        sender = self._pop_sender_txs(sender_address)
        return MPSenderTXs(sender_address=sender_address) if sender is None else sender

    def get_tx_for_execution(self) -> Optional[MPTxRequest]:

        if len(self.senders) == 0:
            return None

        tx: Optional[MPTxRequest] = None
        for sender_txs in self.senders:
            if sender_txs.is_processing():
                continue
            tx = sender_txs.acquire_tx()
            break

        return tx

    def reschedule(self, sender_addr: str, nonce: int):
        sender = self._get_sender_txs(sender_addr)
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
            bisect.insort_left(self.senders, sender)

    def get_pending_trx_count(self, sender_addr: str) -> int:
        sender = self._get_sender_txs(sender_addr)
        return 0 if sender is None else sender.len()
