from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List
from sortedcontainers import SortedList
import unittest


class MPTxStatus(IntEnum):
    Pending = 0
    Confirmed = 1
    Finalized = 2


class MPSenderTXs:
    address: str = None
    txs: SortedList[MPTransaction] = None

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


class MPTransaction:
    signature: str = None
    nonce: int = 0
    neon_tx: TestTrx = None

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


class MPNeonTxScheduler:
    def __init__(self) -> None:
        self.senders: List[MPSenderTXs] = []

    def add_tx(self, tx: MPTransaction):
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


class TestTrx:
    def __init__(self, sender, nonce, gasPrice):
        self.addr = sender
        self.nonce = nonce
        self.gasPrice = gasPrice

    def __str__(self):
        return f"{self.addr}{self.nonce}{self.gasPrice}"

    def sender(self):
        return self.addr


TEST_DATA=[
    MPTransaction(neon_tx=TestTrx("01", 1, 10)),
    MPTransaction(neon_tx=TestTrx("01", 1, 15)),
    MPTransaction(neon_tx=TestTrx("01", 2, 20)),
    MPTransaction(neon_tx=TestTrx("01", 3, 30)),
    MPTransaction(neon_tx=TestTrx("01", 3, 40)),
    MPTransaction(neon_tx=TestTrx("01", 3, 50)),
    MPTransaction(neon_tx=TestTrx("01", 4, 60)),
    MPTransaction(neon_tx=TestTrx("01", 5, 70)),
    MPTransaction(neon_tx=TestTrx("02", 1, 50)),
    MPTransaction(neon_tx=TestTrx("02", 1, 20)),
    MPTransaction(neon_tx=TestTrx("02", 2, 30)),
    MPTransaction(neon_tx=TestTrx("02", 2, 40)),
    MPTransaction(neon_tx=TestTrx("02", 3, 50)),
    MPTransaction(neon_tx=TestTrx("02", 4, 60)),
    MPTransaction(neon_tx=TestTrx("02", 5, 70)),
    MPTransaction(neon_tx=TestTrx("03", 1, 90)),
    MPTransaction(neon_tx=TestTrx("03", 2, 30)),
    MPTransaction(neon_tx=TestTrx("03", 3, 40)),
    MPTransaction(neon_tx=TestTrx("03", 4, 50)),
]
TEST_RESULT=[
    MPTransaction(neon_tx=TestTrx("03", 1, 90)),
    MPTransaction(neon_tx=TestTrx("02", 1, 50)),
    MPTransaction(neon_tx=TestTrx("02", 2, 40)),
    MPTransaction(neon_tx=TestTrx("02", 3, 50)),
    MPTransaction(neon_tx=TestTrx("02", 4, 60)),
    MPTransaction(neon_tx=TestTrx("02", 5, 70)),
    MPTransaction(neon_tx=TestTrx("03", 2, 30)),
    MPTransaction(neon_tx=TestTrx("03", 3, 40)),
    MPTransaction(neon_tx=TestTrx("03", 4, 50)),
    MPTransaction(neon_tx=TestTrx("01", 1, 15)),
    MPTransaction(neon_tx=TestTrx("01", 2, 20)),
    MPTransaction(neon_tx=TestTrx("01", 3, 50)),
    MPTransaction(neon_tx=TestTrx("01", 4, 60)),
    MPTransaction(neon_tx=TestTrx("01", 5, 70)),
]


class Test_Neon_Faucet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scheduler = MPNeonTxScheduler()

    # @unittest.skip("a.i.")
    def test_01_test_order(self):
        for req in TEST_DATA:
            self.scheduler.add_tx(req)
        for i, resp in enumerate(TEST_RESULT):
            tx_request = self.scheduler.get_tx_for_execution()
            self.assertEqual(resp.signature, tx_request.signature)



if __name__ == '__main__':
    unittest.main()
