import unittest
from proxy.testing.mock_server import MockServer
from proxy.airdroper import run_airdropper, StopAirdropperEvent, NewTokenAccountEvent
from multiprocessing import Queue, Process
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

def MockSolana(MockServer):
    def __init__(self, port):
        super().__init__(port)
        self.process_request_mock = MagicMock()
        self.add_url_rule("/", callback=self.process_request)

    def process_requests(self):
        print("SOLANA RPC: ", request.get_json())
        return None

class Test_Airdropper(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        print("testing airdropper")
        cls.address = 'localhost'
        cls.faucet_port = 3333
        cls.solana_port = 4444
        cls.faucet = MockFaucet(cls.faucet_port)
        cls.solana = MockSolana(cls.solana_port)
        cls.walletaddr = "testwalletaddress"
        cls.airdrop_amount = 10
        cls.event_queue = Queue()
        cls.faucet.start()
        cls.faucet.app.app_context()
        cls.airdropper = Process(target=run_airdropper,
                                 args=(cls.address,
                                       cls.faucet_port,
                                       cls.airdrop_amount,
                                       cls.event_queue))
        cls.airdropper.start()

    def test_new_token_account(self):
        self.faucet.request_eth_token_mock.side_effect = [{}]
        self.event_queue.put(NewTokenAccountEvent(self.walletaddr))

        time.sleep(5) # make sure airdropper processed event

        req_json = {"wallet": self.walletaddr, "amount": self.airdrop_amount}
        self.faucet.request_eth_token_mock.assert_called_with(req_json)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.faucet.shutdown_server()
        cls.faucet.join()
        cls.event_queue.put(StopAirdropperEvent())
        cls.airdropper.join()

