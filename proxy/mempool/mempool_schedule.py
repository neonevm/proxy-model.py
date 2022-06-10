import bisect
from typing import List, Optional

from logged_groups import logged_group

from .mempool_api import MPTxRequest


@logged_group("neon.MemPool")
class MPSenderTXs:
    def __init__(self, address: str = None):
        self.address = address
        self.txs: List[MPTxRequest] = []
        self._processing_tx: Optional[MPTxRequest] = None

    def __eq__(self, other):
        return self.first_tx_gas_price() == other.first_tx_gas_price()

    def __lt__(self, other):
        return self.first_tx_gas_price() > other.first_tx_gas_price()

    def add_tx(self, tx: MPTxRequest):
        index = bisect.bisect_left(self.txs, tx)
        if self._processing_tx is not None and tx.nonce == self._processing_tx.nonce:
            self.warn(f"Failed to replace processing tx: {self._processing_tx.__dict__} with: {tx.__dict__}")
            return

        found: MPTxRequest = None if index == len(self.txs) else self.txs[index]
        if found is not None and found.nonce == tx.nonce:
            if found.gas_price < tx.gas_price:
                self.txs[index] = tx
            return
        self.txs.insert(index, tx)

    def get_tx(self):
        assert self.len() > 0
        return self.txs[0]

    def acquire_tx(self):
        if self.is_processing():
            self.error(f"Failed to acquire tx: already processing: {self._processing_tx}")
            return None
        self._processing_tx = self.get_tx()
        return self._processing_tx

    def on_processed(self, tx: MPTxRequest):
        assert tx == self._processing_tx
        self._processing_tx = None
        self.txs.remove(tx)

    def len(self):
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

    def _get_sender_txs(self, sender_address: str) -> Optional[MPSenderTXs]:
        for sender in self.senders:
            if sender.address != sender_address:
                continue
            return sender
        return None

    def add_tx(self, tx: MPTxRequest):
        sender = self._get_sender_or_create(tx.sender_address)
        sender.add_tx(tx)
        self.senders.sort()

    def _get_sender_or_create(self, sender_address: str) -> MPSenderTXs:
        sender = self._get_sender_txs(sender_address)
        if sender is None:
            sender = MPSenderTXs(address=sender_address)
            self.senders.append(sender)
        return sender

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
        sender = self._get_sender_txs(sender_addr)
        if sender is None:
            self.error(f"Failed to make tx done, address: {sender_addr}, nonce: {nonce} - sender not found")
        sender.on_tx_done(nonce)
        if sender.empty():
            self.senders.remove(sender)
        self.senders.sort()

    def get_pending_trx_count(self, sender_addr: str) -> int:
        sender = self._get_sender_txs(sender_addr)
        return sender.len() if sender is not None else 0
