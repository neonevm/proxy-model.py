## File: test_query_account_contract.py
## Integration test for the QueryAccount smart contract.
##
## QueryAccount precompiled contract supports two methods:
##
## metadata(uint256) returns (bytes memory)
##     Takes a Solana address, treats it as an address of an account.
##     If success, returns result code (1 byte), the account's owner (32 bytes) and length of the account's data (8 bytes).
##     Returns empty array otherwise.
##
## data(uint256, uint256, uint256) returns (bytes memory)
##     Takes a Solana address, treats it as an address of an account,
##     also takes an offset and length of the account's data.
##     If success, returns result code (1 byte) and the data (length bytes).
##     Returns empty array otherwise.

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

# Address: HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU
# uint256: 110178555362476360822489549210862241441608066866019832842197691544474470948129

# Address: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
# uint256: 3106054211088883198575105191760876350940303353676611666299516346430146937001

CONTRACT_SOURCE = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0;

contract TestQueryAccount {
    address constant QueryAccount = 0xff00000000000000000000000000000000000002;

    function test_metadata_ok() external returns (bool) {
        uint256 solana_address = 110178555362476360822489549210862241441608066866019832842197691544474470948129;
        (bool success, bytes memory result) = QueryAccount.delegatecall(abi.encodeWithSignature("metadata(uint256)", solana_address));
        require(success);
        if (result.length == 0) {
            return false;
        }
        if (result[0] != 0) {
            return false;
        }
        if (result.length != (1 + 32 + 8)) {
            return false;
        }
        uint256 owner_address = to_uint256(clone_slice(result, 1, 33));
        uint256 golden_owner_address = 3106054211088883198575105191760876350940303353676611666299516346430146937001;
        if (owner_address != golden_owner_address) {
            return false;
        }
        uint64 data_length = to_uint64(clone_slice(result, 33, 41));
        uint64 golden_data_length = 82;
        if (data_length != golden_data_length) {
            return false;
        }
        return true;
    }

    function test_metadata_nonexistent_account() external returns (bool) {
        uint256 solana_address = 90000; // hopefully does not exist
        (bool success, bytes memory result) = QueryAccount.delegatecall(abi.encodeWithSignature("metadata(uint256)", solana_address));
        require(!success);
        return true;
    }

    function test_data_ok() external returns (bool) {
        uint256 solana_address = 110178555362476360822489549210862241441608066866019832842197691544474470948129;
        // Test getting partial data
        uint256 offset = 20;
        uint256 length = 4;
        (bool success, bytes memory result) = QueryAccount.delegatecall(abi.encodeWithSignature("data(uint256,uint256,uint256)", solana_address, offset, length));
        require(success);
        if (result.length == 0) {
            return false;
        }
        if (result[0] != 0) {
            return false;
        }
        byte r1 = 0x71;
        byte r2 = 0x33;
        byte r3 = 0xc6;
        byte r4 = 0x12;
        if (result[1] != r1) {
            return false;
        }
        if (result[2] != r2) {
            return false;
        }
        if (result[3] != r3) {
            return false;
        }
        if (result[4] != r4) {
            return false;
        }
        // Test getting full data
        offset = 0;
        length = 82;
        (success, result) = QueryAccount.delegatecall(abi.encodeWithSignature("data(uint256,uint256,uint256)", solana_address, offset, length));
        require(success);
        if (result.length != (1+82)) { // initial byte stores error code (0==success)
            return false;
        }
        if (result[0] != 0) {
            return false;
        }
        return true;
    }

    function test_data_nonexistent_account() external returns (bool) {
        uint256 solana_address = 90000; // hopefully does not exist
        uint256 offset = 0;
        uint256 length = 1;
        (bool success, bytes memory result) = QueryAccount.delegatecall(abi.encodeWithSignature("data(uint256,uint256,uint256)", solana_address, offset, length));
        require(!success);
        return true;
    }

    function test_data_too_big_offset() external returns (bool) {
        uint256 solana_address = 110178555362476360822489549210862241441608066866019832842197691544474470948129;
        uint256 offset = 200; // data len is 82
        uint256 length = 1;
        (bool success, bytes memory result) = QueryAccount.delegatecall(abi.encodeWithSignature("data(uint256,uint256,uint256)", solana_address, offset, length));
        require(!success);
        return true;
    }

    function test_data_too_big_length() external returns (bool) {
        uint256 solana_address = 110178555362476360822489549210862241441608066866019832842197691544474470948129;
        uint256 offset = 0;
        uint256 length = 200; // data len is 82
        (bool success, bytes memory result) = QueryAccount.delegatecall(abi.encodeWithSignature("data(uint256,uint256,uint256)", solana_address, offset, length));
        require(!success);
        return true;
    }

    function clone_slice(bytes memory source, uint64 left_index, uint64 right_index) private pure returns (bytes memory) {
        require(right_index > left_index);
        bytes memory result = new bytes(right_index - left_index);
        for (uint64 i = left_index; i < right_index; i++) {
            result[i - left_index] = source[i];
        }
        return result;
    }

    function to_uint64(bytes memory bb) private pure returns (uint64 result) {
        assembly {
            result := mload(add(bb, 8))
        }
    }

    function to_uint256(bytes memory bb) private pure returns (uint256 result) {
        assembly {
            result := mload(add(bb, 32))
        }
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
    def test_metadata_ok(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        get_metadata_ok = query.functions.test_metadata_ok().call()
        assert(get_metadata_ok)

    # @unittest.skip("a.i.")
    def test_metadata_nonexistent_account(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        get_metadata_nonexistent_account = query.functions.test_metadata_nonexistent_account().call()
        assert(get_metadata_nonexistent_account)

    # @unittest.skip("a.i.")
    def test_data_ok(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        get_data_ok = query.functions.test_data_ok().call()
        assert(get_data_ok)

    # @unittest.skip("a.i.")
    def test_data_nonexistent_account(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        get_data_nonexistent_account = query.functions.test_data_nonexistent_account().call()
        assert(get_data_nonexistent_account)

    # @unittest.skip("a.i.")
    def test_data_too_big_offset(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        get_data_too_big_offset = query.functions.test_data_too_big_offset().call()
        assert(get_data_too_big_offset)

    # @unittest.skip("a.i.")
    def test_data_too_big_length(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        get_data_too_big_length = query.functions.test_data_too_big_length().call()
        assert(get_data_too_big_length)

if __name__ == '__main__':
    unittest.main()
