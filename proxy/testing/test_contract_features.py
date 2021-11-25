import unittest
import os

import eth_utils

from web3 import Web3, exceptions as web3_exceptions
from solana.rpc.api import Client as SolanaClient

from .testing_helpers import compile_contract


class TestAirdroppingEthAccounts(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        new_user_airdrop_amount = int(os.environ.get("NEW_USER_AIRDROP_AMOUNT", "0"))
        cls._EXPECTED_BALANCE_WEI = eth_utils.to_wei(new_user_airdrop_amount, 'ether')

        proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
        cls._web3 = Web3(Web3.HTTPProvider(proxy_url))
        solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
        cls._solana_client = SolanaClient(solana_url)

    def test_contract_raises_correct_error(self):
        arr_constructable = compile_contract(self._CONTRACT_LIST_CONSTRUCTABLE)
        with self.assertRaises(web3_exceptions.ContractLogicError) as cm:
            arr_constructable.constructor([]).buildTransaction()
        self.assertEqual("ListConstructable: empty list", str(cm.exception))

    _CONTRACT_LIST_CONSTRUCTABLE = '''
        // SPDX-License-Identifier: GPL-3.0
        pragma solidity >=0.7.0 <0.9.0;
        contract ArrConstructable {
            constructor(uint256[] memory vector_) payable {
                require(vector_.length > 0, "ListConstructable: empty list");
            }
        }
    '''
