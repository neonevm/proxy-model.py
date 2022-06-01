import unittest
from proxy.mempool.mempool_api import MPTxRequest
from proxy.mempool.mempool_scheduler import MPNeonTxScheduler


class TestTrx:
    def __init__(self, sender, nonce, gasPrice):
        self.addr = sender
        self.nonce = nonce
        self.gasPrice = gasPrice

    def sender(self):
        return self.addr


TEST_DATA=[
    MPTxRequest(req_id=10, neon_tx=TestTrx("01", 1, 10)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("01", 1, 15)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("01", 2, 20)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("01", 3, 30)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("01", 3, 40)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("01", 3, 50)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("01", 4, 60)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("01", 5, 70)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("02", 1, 50)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("02", 1, 20)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("02", 2, 30)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("02", 2, 40)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("02", 3, 50)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("02", 4, 60)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("02", 5, 70)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("03", 1, 90)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("03", 2, 30)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("03", 3, 40)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("03", 4, 50)),
]
TEST_RESULT=[
    MPTxRequest(req_id=10, neon_tx=TestTrx("03", 1, 90)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("02", 1, 50)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("02", 2, 40)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("02", 3, 50)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("02", 4, 60)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("02", 5, 70)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("03", 2, 30)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("03", 3, 40)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("03", 4, 50)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("01", 1, 15)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("01", 2, 20)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("01", 3, 50)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("01", 4, 60)),
    MPTxRequest(req_id=10, neon_tx=TestTrx("01", 5, 70)),
]


class Test_Neon_Faucet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scheduler = MPNeonTxScheduler()

    # @unittest.skip("a.i.")
    def test_01_test_order(self):
        for req in TEST_DATA:
            self.scheduler.add_tx(req)
        for resp in TEST_RESULT:
            tx_request = self.scheduler.get_tx_for_execution()
            self.assertEqual(resp.gas_price, tx_request.gas_price)
            self.assertEqual(resp.nonce, tx_request.nonce)
            self.assertEqual(resp.address, tx_request.address)


if __name__ == '__main__':
    unittest.main()
