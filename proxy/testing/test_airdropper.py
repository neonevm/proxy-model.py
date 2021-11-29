import unittest
from proxy.testing.mock_server import MockServer
from proxy.indexer.solana_receipts_update import run_indexer
from multiprocessing import Process
import time
from flask import request
from unittest.mock import MagicMock, patch, call
from solana.rpc.api import Client
from solana.rpc.types import RPCResponse
from solana.rpc.providers.http import HTTPProvider
from typing import cast
import itertools
from proxy.testing.transactions import pre_token_airdrop_trx1, pre_token_airdrop_trx2,\
    create_sol_acc_and_airdrop_trx, wrapper_whitelist, evm_loader_addr, token_airdrop_address1, \
    token_airdrop_address2, token_airdrop_address3

class MockFaucet(MockServer):
    def __init__(self, port):
        super().__init__(port)
        self.request_eth_token_mock = MagicMock()
        self.request_eth_token_mock.side_effect = itertools.repeat({})
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


def create_get_signatures_for_address(signatures: list):
    return {
        'jsonrpc': '2.0',
        'result': [ create_signature_for_address(sign) for sign in signatures ],
        'id': 1
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

    def _run_test(self):
        indexer = Process(target=run_indexer,
                          args=(f'http://localhost:8899',  # solana_url
                                evm_loader_addr,
                                True,  # airdropper_mode
                                f'http://{self.address}:{self.faucet_port}',  # faucet_url
                                wrapper_whitelist,
                                self.airdrop_amount))
        indexer.start()
        time.sleep(2)  # make sure airdropper processed event
        indexer.terminate()
        indexer.join()


    @patch.object(Client, 'get_confirmed_transaction')
    @patch.object(HTTPProvider, 'make_request')
    @patch.object(Client, 'get_slot')
    def test_simple_case_one_account_one_airdrop(self, get_slot, make_request, get_confirmed_transaction):
        # Return the same slot on every call (not make sense)
        get_slot.side_effect = itertools.repeat(cast(RPCResponse, { 'error': None, 'id': 1, 'result': 1 }))
        # Will return 2 signatures on first call, empty list all other times
        make_request.side_effect = itertools.chain([create_get_signatures_for_address([ 'signature1', 'signature2' ])],
                                                   itertools.repeat(create_get_signatures_for_address([])))
        # Will return same transaction (with same eth address) for every signature
        get_confirmed_transaction.side_effect = [ pre_token_airdrop_trx1, pre_token_airdrop_trx1 ]

        self._run_test()

        # Should be only one call to faucet
        req_json = {"wallet": token_airdrop_address1, "amount": self.airdrop_amount}
        self.faucet.request_eth_token_mock.assert_called_once_with(req_json)
        self.faucet.request_eth_token_mock.reset_mock()


    @patch.object(Client, 'get_confirmed_transaction')
    @patch.object(HTTPProvider, 'make_request')
    @patch.object(Client, 'get_slot')
    def test_complex_case_two_accounts_two_airdrops(self, get_slot, make_request, get_confirmed_transaction):
        # Return the same slot on every call (not make sense)
        get_slot.side_effect = itertools.repeat(cast(RPCResponse, {'error': None, 'id': 1, 'result': 1}))
        # Will return signature on first call, empty list all other times
        make_request.side_effect = itertools.chain([create_get_signatures_for_address(['signature3'])],
                                                   itertools.repeat(create_get_signatures_for_address([])))
        # Will return complex transaction containing 2 account creations and transfers
        get_confirmed_transaction.side_effect = [pre_token_airdrop_trx2]

        self._run_test()

        # Should be 2 calls to faucet with different addresses
        calls = [ call({"wallet": token_airdrop_address3, "amount": self.airdrop_amount}),
                  call({"wallet": token_airdrop_address2, "amount": self.airdrop_amount}) ]
        self.faucet.request_eth_token_mock.assert_has_calls(calls)
        self.faucet.request_eth_token_mock.reset_mock()

    @patch.object(Client, 'get_confirmed_transaction')
    @patch.object(HTTPProvider, 'make_request')
    @patch.object(Client, 'get_slot')
    def test_should_not_call_faucet(self, get_slot, make_request, get_confirmed_transaction):
        # Return the same slot on every call (not make sense)
        get_slot.side_effect = itertools.repeat(cast(RPCResponse, {'error': None, 'id': 1, 'result': 1}))
        # Will return 2 signatures on first call, empty list all other times
        make_request.side_effect = itertools.chain([create_get_signatures_for_address(['signature4'])],
                                                   itertools.repeat(create_get_signatures_for_address([])))
        # Will return not interesting create_sol_acc_and_airdrop_trx
        get_confirmed_transaction.side_effect = [create_sol_acc_and_airdrop_trx]

        self._run_test()

        self.faucet.request_eth_token_mock.assert_not_called()
        self.faucet.request_eth_token_mock.reset_mock()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.faucet.shutdown_server()
        cls.faucet.join()

