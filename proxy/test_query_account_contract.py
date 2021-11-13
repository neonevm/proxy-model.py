## File: test_query_account_contract.py
## Integration test for the QueryAccount smart contract.
##
## QueryAccount precompiled contract supports two methods:
##
## metadata(uint256) returns (bytes memory)
##     Takes a Solana address, treats it as an address of an account.
##     Returns the account's owner and length of the account's data.
##
## data(uint256, uint256, uint256) returns (bytes memory)
##     Takes a Solana address, treats it as an address of an account,
##     also takes an offset and length of the account's data.
##     Returns the success flag, the account's owner and the data.
##     The success flag would have been false if no account found or any error happened.

import unittest
import os
from web3 import Web3
from solcx import install_solc
install_solc(version='0.7.6')
from solcx import compile_source

issue = 'https://github.com/neonlabsorg/neon-evm/issues/360'
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
admin = proxy.eth.account.create(issue + '/admin')
user = proxy.eth.account.create(issue + '/user')
proxy.eth.default_account = admin.address

CONTRACT_SOURCE = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0;

contract TestQueryAccount {
    address constant QueryAccount = 0xff00000000000000000000000000000000000002;

    function test_metadata() external returns (uint256) {
        uint256 solana_address = 255;
        (bool success, bytes memory result) = QueryAccount.delegatecall(abi.encodeWithSignature("metadata(uint256)", solana_address));
        require(success);
        return result.length;
    }

    function test_data() external returns (uint256) {
        uint256 solana_address = 255;
        uint256 offset = 0;
        uint256 length = 64;
        (bool success, bytes memory result) = QueryAccount.delegatecall(abi.encodeWithSignature("data(uint256,uint256,uint256)", solana_address, offset, length));
        require(success);
        return result.length;
    }
}
'''

class Test_Query_Account_Contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print('\n\n' + issue)
        print('user address:', user.address)
        cls.deploy_contract(cls)

    def deploy_contract(self):
        compiled = compile_source(CONTRACT_SOURCE)
        id, interface = compiled.popitem()
        self.contract = interface
        contract = proxy.eth.contract(abi=self.contract['abi'], bytecode=self.contract['bin'])
        nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx = {'nonce': nonce}
        tx_constructor = contract.constructor().buildTransaction(tx)
        tx_deploy = proxy.eth.account.sign_transaction(tx_constructor, admin.key)
        tx_deploy_hash = proxy.eth.send_raw_transaction(tx_deploy.rawTransaction)
        tx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        self.contract_address = tx_deploy_receipt.contractAddress

    # @unittest.skip("a.i.")
    def test_query_metadata(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        r = query.functions.test_metadata().call()
        print('type(r):', type(r))
        print('r:', r)

    # @unittest.skip("a.i.")
    def test_query_data(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        r = query.functions.test_data().call()
        print('type(r):', type(r))
        print('r:', r)

if __name__ == '__main__':
    unittest.main()
