import unittest
from proxy.testing.mock_server import MockServer
from proxy.airdroper import run_airdropper, StopAirdropperEvent, NewTokenAccountEvent
from multiprocessing import Queue, Process
import requests
from flask import Flask, request, jsonify
from unittest.mock import patch, MagicMock
from threading import Thread
import json

class MockFaucet(Thread):
    def __init__(self, port):
        super().__init__()
        self.port = port
        self.app = Flask(__name__)
        self.url = "http://localhost:%s" % self.port
        self.app.add_url_rule("/request_eth_token",
                              view_func=self.request_eth_token,
                              methods=['POST'])

        self.app.add_url_rule("/shutdown", view_func=self._shutdown_server)

    def _shutdown_server(self):
        if not 'werkzeug.server.shutdown' in request.environ:
            raise RuntimeError('Not running the development server')
        request.environ['werkzeug.server.shutdown']()
        return 'Server shutting down...'

    def run(self):
        self.app.run(port=self.port)

    def shutdown_server(self):
        requests.get("http://localhost:%s/shutdown" % self.port)
        self.join()

    def request_eth_token(self):
        return jsonify({})

class Test_Airdropper(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        print("testing airdropper")
        cls.address = 'localhost'
        cls.port = 3333
        cls.faucet_mock = MockFaucet(cls.port)
        cls.airdrop_amount = 10
        cls.event_queue = Queue()
        cls.airdropper_proc = Process(target=run_airdropper,
                                      args=(cls.address,
                                            cls.port,
                                            cls.airdrop_amount,
                                            cls.event_queue))
        cls.airdropper_proc.start()
        cls.faucet_mock.start()

    def test_new_token_account(self):
        walletaddr = "testwalletaddress"
        airdropamount = 10

        self.event_queue.put(NewTokenAccountEvent(walletaddr))
        res = requests.post(f"http://{self.address}:{self.port}/request_eth_token",
                            json={ "wallet": walletaddr, "amount": airdropamount })
        if not res.ok:
            print('Response:', res.status_code)
        assert (res.ok)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.event_queue.put(StopAirdropperEvent())
        cls.airdropper_proc.join()
        cls.faucet_mock.shutdown_server()
        cls.faucet_mock.join()

