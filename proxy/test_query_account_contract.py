## File: test_query_account_contract.py
## Integration test for the QueryAccount smart contract.

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

QUERY_ACCOUNT_INTERFACE_SOURCE = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0;

interface IQueryAccount {
    function metadata(address to) external returns (bytes memory);
}
'''

QUERY_ACCOUNT_CONTRACT_SOURCE = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0;

contract QueryAccount {
    address constant NeonQueryAccount = 0xff00000000000000000000000000000000000002;

    fallback() external {
        bytes memory call_data = abi.encodePacked(msg.data);
        (bool success, bytes memory result) = NeonQueryAccount.delegatecall(call_data);

        require(success, string(result));

        assembly {
            return(add(result, 0x20), mload(result))
        }
    }
}
'''

class Test_Query_Account_Contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print('\n\n' + issue)
        cls.deploy_contract(cls)

    def deploy_contract(self):
        compiled = compile_source(QUERY_ACCOUNT_INTERFACE_SOURCE)
        id, interface = compiled.popitem()
        self.interface = interface

        compiled = compile_source(QUERY_ACCOUNT_CONTRACT_SOURCE)
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
        contract = proxy.eth.contract(address=self.contract_address, abi=self.interface['abi'])
        nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx = {'nonce': nonce}
        tx = contract.functions.metadata(user.address).buildTransaction(tx)
        tx = proxy.eth.account.sign_transaction(tx, admin.key)
        tx_hash = proxy.eth.send_raw_transaction(tx.rawTransaction)
        tx_receipt = proxy.eth.wait_for_transaction_receipt(tx_hash)
        self.assertIsNotNone(tx_receipt)

if __name__ == '__main__':
    unittest.main()
