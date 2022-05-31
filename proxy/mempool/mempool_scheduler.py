from typing import List
from sortedcontainers import SortedList
from .mempool_api import MPTxRequest
from ..common_neon.eth_proto import Trx as NeonTx


class MPTransaction:
    signature: str = None
    nonce: int = 0
    neon_tx: NeonTx = None

    def __init__(self, neon_tx):
        self.neon_tx = neon_tx
        self.signature = str(neon_tx)
        self.nonce = neon_tx.nonce

    def __eq__(self, other):
        return self.nonce == other.nonce

    def __lt__(self, other):
        return self.nonce < other.nonce

    def __str__(self):
        return self.signature

    @property
    def address(self):
        return self.neon_tx.addr

    def gas_price(self):
        return self.neon_tx.gasPrice


class MPSenderTXs:
    # address: str = None
    # txs: SortedList[MPTransaction] = None

    def __init__(self, address: str = None) -> None:
        self.address = address
        self.txs = SortedList()

    def __eq__(self, other):
        return self.first_tx_gas_price() == other.first_tx_gas_price()

    def __lt__(self, other):
        return self.first_tx_gas_price() > other.first_tx_gas_price()

    def add_tx(self, tx: MPTransaction):
        self.txs.add(tx)
        start_index = self.txs.index(tx)
        while start_index + 1 < len(self.txs) and self.txs[start_index] == self.txs[start_index + 1]:
            if self.txs[start_index].gas_price() < self.txs[start_index + 1].gas_price():
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
        return self.txs[0].gas_price()


class MPNeonTxScheduler:
    def __init__(self) -> None:
        self.senders: List[MPSenderTXs] = []

    def add_tx(self, mp_request: MPTxRequest):
        tx = MPTransaction(mp_request)
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
        return tx.mp_request


class MPTransaction:
    # mp_request: MPTxRequest = None
    # signature: str = None
    # nonce: int = 0
    # address: str = None
    # gas_price: int = 0

    def __init__(self, mp_request: MPTxRequest):
        self.mp_request = mp_request
        self.signature  = mp_request.signature
        self.nonce      = mp_request.neon_tx.nonce
        self.address    = mp_request.neon_tx.sender()
        self.gas_price  = mp_request.neon_tx.gasPrice

    def __eq__(self, other):
        return self.nonce == other.nonce

    def __lt__(self, other):
        return self.nonce < other.nonce
