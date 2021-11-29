import unittest
from proxy.testing.mock_server import MockServer
from proxy.indexer.solana_receipts_update import run_indexer
from multiprocessing import Process
import time
from flask import request
from unittest.mock import MagicMock, patch
from solana.rpc.api import Client
from solana.rpc.types import RPCResponse
from solana.rpc.providers.http import HTTPProvider
from typing import cast
import itertools
from proxy.testing.transactions import pre_token_airdrop_trx1, pre_token_airdrop_trx2,\
    create_sol_acc_and_airdrop_trx, wrapper_whitelist, evm_loader_addr, token_airdrop_address1

class MockFaucet(MockServer):
    def __init__(self, port):
        super().__init__(port)
        self.request_eth_token_mock = MagicMock()
        self.add_url_rule("/request_eth_token", callback=self.request_eth_token, methods=['POST'])

    def request_eth_token(self):
        req = request.get_json()
        return self.request_eth_token_mock(req)


def create_signature_for_address(signature: str):
    return {
        'blockTime': 1638177745, # not make sense
        'confirmationStatus': 'finalized',
        'err': None,
        'memo': None,
        'signature': signature,
        'slot': 9748200 # not make sense
    }


def create_get_signatures_for_address(signatures: list, req_id: int):
    return {
        'jsonrpc': '2.0',
        'result': [ create_signature_for_address(sign) for sign in signatures ],
        'id': req_id
    }


class Test_Airdropper(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        print("testing indexer in airdropper mode")
        cls.address = 'localhost'
        cls.faucet_port = 3333
        cls.airdrop_amount = 10

        cls.faucet = MockFaucet(cls.faucet_port)
        cls.faucet.start()
        time.sleep(0.2)

    @patch.object(Client, 'get_confirmed_transaction')
    @patch.object(HTTPProvider, 'make_request')
    @patch.object(Client, 'get_slot')
    def test_new_token_account(self, get_slot, make_request, get_confirmed_transaction):
        # Return the same slot on every call (not make sense)
        get_slot.side_effect = itertools.repeat(cast(RPCResponse, { 'error': None, 'id': 1, 'result': 1 }))
        # Will return 2 signatures on first call, empty list all other times
        make_request.side_effect = itertools.chain([create_get_signatures_for_address([ 'signature1', 'signature2' ], 2)],
                                                   itertools.repeat(create_get_signatures_for_address([], 3)))
        # Will return pre_token_airdrop_trx1 for signature1, create_sol_acc_and_airdrop_trx for signature2
        get_confirmed_transaction.side_effect = [ pre_token_airdrop_trx1, create_sol_acc_and_airdrop_trx ]
        self.faucet.request_eth_token_mock.side_effect = [{}]


        indexer = Process(target=run_indexer,
                          args=(f'http://localhost:8899', # solana_url
                                evm_loader_addr,
                                True,  # airdropper_mode
                                f'http://{self.address}:{self.faucet_port}',  # faucet_url
                                wrapper_whitelist,
                                self.airdrop_amount))
        indexer.start()

        time.sleep(1) # make sure airdropper processed event

        indexer.terminate()
        indexer.join()

        #make_request.assert_called()
        req_json = {"wallet": token_airdrop_address1, "amount": self.airdrop_amount}
        self.faucet.request_eth_token_mock.assert_called_with(req_json)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.faucet.shutdown_server()
        cls.faucet.join()

