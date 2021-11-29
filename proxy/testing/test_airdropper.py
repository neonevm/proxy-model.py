import unittest
from proxy.testing.mock_server import MockServer
from proxy.indexer.solana_receipts_update import run_indexer
from multiprocessing import Process
import time
from flask import request
from unittest.mock import MagicMock

class MockFaucet(MockServer):
    def __init__(self, port):
        super().__init__(port)
        self.request_eth_token_mock = MagicMock()
        self.add_url_rule("/request_eth_token", callback=self.request_eth_token, methods=['POST'])

    def request_eth_token(self):
        req = request.get_json()
        return self.request_eth_token_mock(req)

class MockSolana(MockServer):
    def __init__(self, port):
        super().__init__(port)
        self.process_request_mock = MagicMock()
        self.add_url_rule("/", callback=self.process_request, methods=['GET', 'POST'])

    def process_request(self):
        print("SOLANA RPC: ", request.get_json())
        return {}

class Test_Airdropper(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        print("testing indexer in airdropper mode")
        cls.address = 'localhost'
        cls.evm_loader_id = 'testevmloaderid'
        cls.faucet_port = 3333
        cls.solana_port = 4444
        cls.walletaddr = "testwalletaddress"
        cls.airdrop_amount = 10
        cls.wrapper_whitelist = []

        cls.faucet = MockFaucet(cls.faucet_port)
        cls.faucet.start()
        cls.solana = MockSolana(cls.solana_port)
        cls.solana.start()

        time.sleep(10)

        cls.indexer = Process(target=run_indexer,
                              args=(f'http://solana:8899',  # solana_url
                                    cls.evm_loader_id,
                                    True,                                       # airdropper_mode
                                    f'http://{cls.address}:{cls.faucet_port}',  # faucet_url
                                    cls.wrapper_whitelist))
        cls.indexer.start()

    def test_new_token_account(self):
        #self.faucet.request_eth_token_mock.side_effect = [{}]

        time.sleep(15) # make sure airdropper processed event

        #req_json = {"wallet": self.walletaddr, "amount": self.airdrop_amount}
        #self.faucet.request_eth_token_mock.assert_called_with(req_json)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.solana.shutdown_server()
        cls.faucet.shutdown_server()
        cls.indexer.terminate()
        cls.indexer.join()
        cls.solana.join()
        cls.faucet.join()

