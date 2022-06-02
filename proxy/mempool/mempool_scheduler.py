from typing import List
from sortedcontainers import SortedList
from .mempool_api import MPTxRequest


class MPSenderTXs:
    def __init__(self, address: str = None):
        self.address = address
        self.txs = SortedList()

    def __eq__(self, other):
        return self.first_tx_gas_price() == other.first_tx_gas_price()

    def __lt__(self, other):
        return self.first_tx_gas_price() > other.first_tx_gas_price()

    def add_tx(self, tx: MPTxRequest):
        self.txs.add(tx)
        start_index = self.txs.index(tx)
        while start_index + 1 < len(self.txs) and self.txs[start_index] == self.txs[start_index + 1]:
            if self.txs[start_index].gas_price < self.txs[start_index + 1].gas_price:
                self.txs.pop(start_index)
            else:
                self.txs.pop(start_index + 1)

    def get_tx(self):
        return self.txs.pop(0)

    def len(self):
        return len(self.txs)

    def first_tx_gas_price(self):
        if len(self.txs) == 0:
            return 0
        return self.txs[0].gas_price


class MPNeonTxScheduler:
    def __init__(self) -> None:
        self.senders: List[MPSenderTXs] = []

    def add_tx(self, tx: MPTxRequest):
        for sender in self.senders:
            if sender.address == tx.address:
                sender.add_tx(tx)
                self.senders.sort()
                return
        sender = MPSenderTXs(address=tx.address)
        sender.add_tx(tx)
        self.senders.append(sender)
        self.senders.sort()

    def get_tx_for_execution(self):
        if len(self.senders) == 0:
            return None
        tx = self.senders[0].get_tx()
        if self.senders[0].len() == 0:
            del self.senders[0]
        self.senders.sort()
        return tx
