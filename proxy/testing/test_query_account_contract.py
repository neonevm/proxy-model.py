## File: test_query_account_contract.py
## Integration test for the QueryAccount smart contract.
##
## QueryAccount precompiled contract methods:
##------------------------------------------
## cache(uint256,uint64,uint64) => 0x2b3c8322
## owner(uint256)               => 0xa123c33e
## length(uint256)              => 0xaa8b99d2
## lamports(uint256)            => 0x748f2d8a
## executable(uint256)          => 0xc219a785
## rent_epoch(uint256)          => 0xc4d369b5
## data(uint256,uint64,uint64)  => 0x43ca5161
##------------------------------------------

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
proxy.eth.default_account = admin.address

# Address: HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU (a token mint account)
# uint256: 110178555362476360822489549210862241441608066866019832842197691544474470948129

# Address: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA (owner of the account)
# uint256: 3106054211088883198575105191760876350940303353676611666299516346430146937001

CONTRACT_SOURCE = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0;

contract QueryAccount {
    address constant precompiled = 0xff00000000000000000000000000000000000002;

    // Takes a Solana address, treats it as an address of an account.
    // Puts the metadata and a chunk of data into the cache.
    function cache(uint256 solana_address, uint64 offset, uint64 len) public returns (bool) {
        (bool success, bytes memory _dummy) = precompiled.staticcall(abi.encodeWithSignature("cache(uint256,uint64,uint64)", solana_address, offset, len));
        return success;
    }

    // Takes a Solana address, treats it as an address of an account.
    // Returns the account's owner Solana address (32 bytes).
    function owner(uint256 solana_address) public view returns (bool, uint256) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("owner(uint256)", solana_address));
        return (success, to_uint256(result));
    }

    // Takes a Solana address, treats it as an address of an account.
    // Returns the length of the account's data (8 bytes).
    function length(uint256 solana_address) public view returns (bool, uint256) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("length(uint256)", solana_address));
        return (success, to_uint256(result));
    }

    // Takes a Solana address, treats it as an address of an account.
    // Returns the funds in lamports of the account.
    function lamports(uint256 solana_address) public view returns (bool, uint256) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("lamports(uint256)", solana_address));
        return (success, to_uint256(result));
    }

    // Takes a Solana address, treats it as an address of an account.
    // Returns the executable flag of the account.
    function executable(uint256 solana_address) public view returns (bool, bool) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("executable(uint256)", solana_address));
        return (success, to_bool(result));
    }

    // Takes a Solana address, treats it as an address of an account.
    // Returns the rent epoch of the account.
    function rent_epoch(uint256 solana_address) public view returns (bool, uint256) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("rent_epoch(uint256)", solana_address));
        return (success, to_uint256(result));
    }

    // Takes a Solana address, treats it as an address of an account,
    // also takes an offset and length of the account's data.
    // Returns a chunk of the data (length bytes).
    function data(uint256 solana_address, uint64 offset, uint64 len) public view returns (bool, bytes memory) {
        return precompiled.staticcall(abi.encodeWithSignature("data(uint256,uint64,uint64)", solana_address, offset, len));
    }

    function to_uint256(bytes memory bb) private pure returns (uint256 result) {
        assembly {
            result := mload(add(bb, 32))
        }
    }

    function to_bool(bytes memory bb) private pure returns (bool result) {
        assembly {
            result := mload(add(bb, 32))
        }
    }
}

contract TestQueryAccount is QueryAccount {
    uint256 constant solana_account = 110178555362476360822489549210862241441608066866019832842197691544474470948129;
    uint256 constant missing_account = 90000;

    function test_cache() public returns (bool) {
        // Put
        bool ok = super.cache(solana_account, 0, 64);
        if (!ok) { return false; }

        // Replace
        ok = super.cache(solana_account, 0, 82);
        if (!ok) { return false; }

        // Zero length
        ok = super.cache(solana_account, 0, 0);
        if (ok) { return false; }

        // Length too long
        ok = super.cache(solana_account, 0, 200);
        if (ok) { return false; }

        // Offset too big
        ok = super.cache(solana_account, 200, 16);
        if (ok) { return false; }

        // Nonexistent account
        ok = super.cache(missing_account, 0, 1);
        if (ok) { return false; }

        return true;
    }

    function test_noncached() public returns (bool) {
        bool ok;
        uint256 _u;
        bool _b;
        bytes memory _m;

        (ok, _u) = super.owner(solana_account);
        if (ok) { return false; }

        (ok, _u) = super.length(solana_account);
        if (ok) { return false; }

        (ok, _u) = super.lamports(solana_account);
        if (ok) { return false; }

        (ok, _b) = super.executable(solana_account);
        if (ok) { return false; }

        (ok, _u) = super.rent_epoch(solana_account);
        if (ok) { return false; }

        (ok, _m) = super.data(solana_account, 0, 1);
        if (ok) { return false; }

        return true;
    }

    function test_metadata_ok() public returns (bool) {
        bool ok = super.cache(solana_account, 0, 64);
        if (!ok) { return false; }

        uint256 golden_owner = 3106054211088883198575105191760876350940303353676611666299516346430146937001;
        uint256 golden_len = 82;
        uint256 golden_lamp = 1461600;
        bool golden_exec = false;

        uint256 ownr;
        (ok, ownr) = super.owner(solana_account);
        if (!ok || ownr != golden_owner) {
            return false;
        }

        uint len;
        (ok, len) = super.length(solana_account);
        if (!ok || len != golden_len) {
            return false;
        }

        uint256 lamp;
        (ok, lamp) = super.lamports(solana_account);
        if (!ok || lamp != golden_lamp) {
            return false;
        }

        bool exec;
        (ok, exec) = super.executable(solana_account);
        if (!ok || exec != golden_exec) {
            return false;
        }

        uint256 _repoch; // epoch may change, so there is no golden value
        (ok, _repoch) = super.rent_epoch(solana_account);
        if (!ok) {
            return false;
        }

        return true;
    }

    function test_data_ok() public returns (bool) {
        bool ok = super.cache(solana_account, 0, 64);
        if (!ok) { return false; }

        byte b0 = 0x71;
        byte b1 = 0x33;
        byte b2 = 0xc6;
        byte b3 = 0x12;

        // Get subset of data
        uint64 offset = 20;
        uint64 len = 4;
        bytes memory result;
        (ok, result) = super.data(solana_account, offset, len);
        if (!ok) {
            return false;
        }
        if (result.length != 4) {
            return false;
        }
        if (result[0] != b0) {
            return false;
        }
        if (result[1] != b1) {
            return false;
        }
        if (result[2] != b2) {
            return false;
        }
        if (result[3] != b3) {
            return false;
        }

        // Get full data
        offset = 0;
        len = 64;
        (ok, result) = super.data(solana_account, offset, len);
        if (!ok || result.length != 64) {
            return false;
        }

        return true;
    }

    function test_data_too_big_offset() public returns (bool) {
        bool ok = super.cache(solana_account, 0, 82);
        if (!ok) { return false; }

        uint64 offset = 200; // data len is 82
        uint64 len = 1;
        bytes memory _m;
        (ok, _m) = super.data(solana_account, offset, len);
        if (ok) { return false; }

        return true;
    }

    function test_data_too_big_length() public returns (bool) {
        bool ok = super.cache(solana_account, 0, 82);
        if (!ok) { return false; }

        uint64 offset = 0;
        uint64 len = 200; // data len is 82
        bytes memory _m;
        (ok, _m) = super.data(solana_account, offset, len);
        if (ok) { return false; }

        return true;
    }
}
'''

class Test_Query_Account_Contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print('\n\n' + issue)
        print('admin address:', admin.address)
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
        print('contract address:', self.contract_address)

    # @unittest.skip("a.i.")
    def test_cache(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        ok = query.functions.test_cache().call()
        assert(ok)

    # @unittest.skip("a.i.")
    def test_noncached(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        ok = query.functions.test_noncached().call()
        assert(ok)

    # @unittest.skip("a.i.")
    def test_metadata_ok(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        ok = query.functions.test_metadata_ok().call()
        assert(ok)

    # @unittest.skip("a.i.")
    def test_data_ok(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        ok = query.functions.test_data_ok().call()
        assert(ok)

    # @unittest.skip("a.i.")
    def test_data_too_big_offset(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        ok = query.functions.test_data_too_big_offset().call()
        assert(ok)

    # @unittest.skip("a.i.")
    def test_data_too_big_length(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        ok = query.functions.test_data_too_big_length().call()
        assert(ok)

if __name__ == '__main__':
    unittest.main()
