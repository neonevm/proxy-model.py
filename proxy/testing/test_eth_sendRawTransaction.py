import unittest
import json
import random
from typing import List
import eth_utils

from .testing_helpers import Proxy, TxReceipt, HexBytes


STORAGE_SOLIDITY_SOURCE_147 = '''
pragma solidity >=0.7.0 <0.9.0;
/**
 * @title Storage
 * @dev Store & retrieve value in a variable
 */
contract Storage {
    uint256 number;
    /**
     * @dev Store value in variable
     * @param num value to store
     */
    function store(uint256 num) public {
        number = num;
    }
    /**
     * @dev Return value
     * @return value of 'number'
     */
    function retrieve() public view returns (uint256){
        return number;
    }
}
'''

SOLIDITY_SOURCE_185 = '''
pragma solidity >=0.7.0 <0.9.0;

contract test_185 {
    bytes public emprty_string = "";

    function getKeccakOfEmptyString() public view returns (bytes32 variant) {
        variant = keccak256(emprty_string);
    }

    bytes32 constant neonlabsHash = keccak256("neonlabs");

    function endlessCycle() public view returns (bytes32 variant) {
        variant = keccak256(emprty_string);
        for(;neonlabsHash != variant;) {
            variant = keccak256(abi.encodePacked(variant));
        }
        return variant;
    }

    bytes32 public value = "";

    function initValue(string memory s) public {
        value = keccak256(bytes(s));
    }

    function calculateKeccakAndStore(uint256 times) public {
        bytes32 v = value;
        for(;times > 0; --times) {
            v = keccak256(abi.encodePacked(v));
        }

        value = v;
    }

    function getValue() public view returns (bytes32) {
        return value;
    }

}
'''


class TestEthSendRawTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/147")
        cls.proxy = proxy = Proxy()
        cls.eth_account = eth_account = proxy.create_signer_account(
            'https://github.com/neonlabsorg/proxy-model.py/issues/147'
        )
        print('eth_account.address:', eth_account.address)
        print('eth_account.key:', eth_account.key.hex())
        cls.deploy_storage_147_solidity_contract(cls)
        cls.deploy_test_185_solidity_contract(cls)

    @staticmethod
    def decode_error(e: Exception) -> dict:
        print(f'type(e): {type(e)}')
        print(f'e: {e}')
        response = json.loads(str(e).replace('\'', '\"').replace('None', 'null'))
        print(f'response: {response}')
        return response

    def deploy_storage_147_solidity_contract(self):
        deployed_info = self.proxy.compile_and_deploy_contract(self.eth_account, STORAGE_SOLIDITY_SOURCE_147)
        self.tx_deploy_hash = deployed_info.tx_hash
        self.deploy_block_hash = deployed_info.tx_receipt['blockHash']
        self.deploy_block_num = deployed_info.tx_receipt['blockNumber']
        self.storage_contract = deployed_info.contract
        print(f'deployed tx_hash {deployed_info.tx_hash.hex()}')

    def deploy_test_185_solidity_contract(self):
        deployed_info = self.proxy.compile_and_deploy_contract(self.eth_account, SOLIDITY_SOURCE_185)
        self.test_185_solidity_contract = deployed_info.contract
        print(f'test_185 tx_hash {deployed_info.tx_hash.hex()}')

    # @unittest.skip("a.i.")
    def test_check_get_block_by_hash(self):
        print("\ntest_check_get_block_by_hash")
        block = self.proxy.conn.get_block(self.deploy_block_hash, full_transactions=True)
        print('block:', block)
        has_tx = False
        for tx in block['transactions']:
            if tx['hash'] == self.tx_deploy_hash:
                has_tx = True
                break
        self.assertTrue(has_tx)

    # @unittest.skip("a.i.")
    def test_check_get_block_by_number(self):
        print("\ntest_check_get_block_by_number")
        block = self.proxy.conn.get_block(int(self.deploy_block_num))
        print('block:', block)
        has_tx = False
        for tx in block['transactions']:
            if tx == self.tx_deploy_hash:
                has_tx = True
                break
        self.assertTrue(has_tx)

    # @unittest.skip("a.i.")
    def test_01_call_retrieve_right_after_deploy(self):
        print("\ntest_01_call_retrieve_right_after_deploy")
        number = self.storage_contract.functions.retrieve().call()
        print('number:', number)
        self.assertEqual(number, 0)

    # @unittest.skip("a.i.")
    def test_02_execute_with_right_nonce(self):
        print("\ntest_02_execute_with_right_nonce")
        tx_store = self.storage_contract.functions.store(147).build_transaction()
        tx_store = self.proxy.sign_send_wait_transaction(self.eth_account, tx_store)
        print(f'trx_store: {tx_store}')

        number = self.storage_contract.functions.retrieve().call()
        print(f'number: {number}')
        self.assertEqual(number, 147)

    # @unittest.skip("a.i.")
    def test_03_execute_with_low_gas(self):
        print("\ntest_03_execute_with_low_gas")
        tx_store = self.storage_contract.functions.store(148).build_transaction({'gas': 0})
        print(f'tx_store: {tx_store}')
        tx_store = self.proxy.sign_transaction(self.eth_account, tx_store)
        print(f'trx_store_signed: {tx_store}')

        try:
            tx_store_hash = self.proxy.conn.send_raw_transaction(tx_store.tx_signed.rawTransaction)
            print(f'trx_store_hash: {tx_store_hash}')
            self.assertTrue(False)
        except Exception as e:
            response = self.decode_error(e)
            self.assertEqual(response['code'], -32000)
            message = 'gas limit reached'
            self.assertEqual(response['message'][:len(message)], message)

    # @unittest.skip("a.i.")
    def test_05_transfer_one_gwei(self):
        print("\ntest_05_transfer_one_gwei")

        eth_account_alice = self.proxy.create_signer_account('alice')
        eth_account_bob = self.proxy.create_signer_account('bob')
        print('eth_account_alice.address:', eth_account_alice.address)
        print('eth_account_bob.address:', eth_account_bob.address)

        if True:
            print("add funds to alice and bob")

            print("alice")
            tx_transfer = self.proxy.sign_send_wait_transaction(
                self.eth_account,
                dict(
                    to=eth_account_alice.address,
                    value=eth_utils.denoms.gwei
                )
            )
            print(f'tx_transfer: {tx_transfer}')

            print("bob")
            tx_transfer = self.proxy.sign_send_wait_transaction(
                self.eth_account,
                dict(
                    to=eth_account_bob.address,
                    value=eth_utils.denoms.gwei
                )
            )
            print(f'tx_transfer: {tx_transfer}')

        alice_balance_before_transfer = self.proxy.conn.get_balance(eth_account_alice.address)
        bob_balance_before_transfer = self.proxy.conn.get_balance(eth_account_bob.address)
        print(f'alice_balance_before_transfer: {alice_balance_before_transfer}')
        print(f'bob_balance_before_transfer: {bob_balance_before_transfer}')
        print(f'one_gwei: {eth_utils.denoms.gwei}')

        tx_transfer = self.proxy.sign_send_wait_transaction(
            eth_account_alice,
            dict(
                to=eth_account_bob.address,
                value=eth_utils.denoms.gwei
            )
        )
        print(f'tx_transfer: {tx_transfer}')

        alice_balance_after_transfer = self.proxy.conn.get_balance(eth_account_alice.address)
        bob_balance_after_transfer = self.proxy.conn.get_balance(eth_account_bob.address)
        print(f'alice_balance_after_transfer: {alice_balance_after_transfer}')
        print(f'bob_balance_after_transfer: {bob_balance_after_transfer}')
        self.assertLessEqual(alice_balance_after_transfer, alice_balance_before_transfer - eth_utils.denoms.gwei)
        self.assertEqual(bob_balance_after_transfer, bob_balance_before_transfer + eth_utils.denoms.gwei)

    # @unittest.skip("a.i.")
    def test_06_transfer_one_and_a_half_gweis(self):
        print("\ntest_06_transfer_one_and_a_half_gweis")

        eth_account_alice = self.proxy.create_signer_account('alice-1')
        eth_account_bob = self.proxy.create_signer_account('bob-1')
        print(f'eth_account_alice.address: {eth_account_alice.address}')
        print('eth_account_bob.address: {eth_account_bob.address}')

        if True:
            print("add funds to alice and bob")

            print("alice")
            tx_transfer = self.proxy.sign_send_wait_transaction(
                self.eth_account,
                dict(
                    to=eth_account_alice.address,
                    value=2 * eth_utils.denoms.gwei
                ),
            )
            print(f'tx_transfer: {tx_transfer}')

            print("bob")
            tx_transfer = self.proxy.sign_send_wait_transaction(
                self.eth_account,
                dict(
                    to=eth_account_bob.address,
                    value=2 * eth_utils.denoms.gwei
                ),
            )
            print(f'tx_transfer: {tx_transfer}')

        alice_balance_before_transfer = self.proxy.conn.get_balance(eth_account_alice.address)
        bob_balance_before_transfer = self.proxy.conn.get_balance(eth_account_bob.address)
        print(f'alice_balance_before_transfer: {alice_balance_before_transfer}')
        print(f'bob_balance_before_transfer: {bob_balance_before_transfer}')
        one_and_a_half_galan = 1_500_000_000
        print(f'one_and_a_half_galan: {one_and_a_half_galan}')

        tx_transfer = self.proxy.sign_send_wait_transaction(
            eth_account_alice,
            dict(
                to=eth_account_bob.address,
                value=one_and_a_half_galan
            ),
        )
        print(f'tx_transfer: {tx_transfer}')

        gas_cost = tx_transfer.tx_receipt['gasUsed'] * tx_transfer.tx['gasPrice']
        print(f'gas_cost: {gas_cost}')

        alice_balance_after_transfer = self.proxy.conn.get_balance(eth_account_alice.address)
        bob_balance_after_transfer = self.proxy.conn.get_balance(eth_account_bob.address)
        print(f'alice_balance_after_transfer: {alice_balance_after_transfer}')
        print(f'bob_balance_after_transfer: {bob_balance_after_transfer}')
        self.assertEqual(alice_balance_after_transfer, alice_balance_before_transfer - one_and_a_half_galan - gas_cost)
        self.assertEqual(bob_balance_after_transfer, bob_balance_before_transfer + one_and_a_half_galan)

    # @unittest.skip("a.i.")
    def test_07_execute_long_transaction(self):
        print("\ntest_07_execute_long_transaction")
        contract = self.test_185_solidity_contract
        tx_init_value = contract.functions.initValue('185 init value').build_transaction()
        tx_init_value = self.proxy.sign_send_wait_transaction(self.eth_account, tx_init_value)
        print(f'trx_initValue: {tx_init_value}')

        value = contract.functions.getValue().call()
        print('value:', value.hex())
        self.assertEqual(value.hex(), '36fb9ea61aba18555110881836366c8d7701685174abe4926673754580ee26c5')

        from datetime import datetime
        start = datetime.now()

        times_to_calculate = 1000
        tx_calculate = contract.functions.calculateKeccakAndStore(times_to_calculate).build_transaction()
        tx_calculate = self.proxy.sign_send_wait_transaction(self.eth_account, tx_calculate)
        print(f'trx_calculate: {tx_calculate}')

        time_duration = datetime.now() - start

        value = contract.functions.getValue().call()
        print(f'value: {value.hex()}')
        self.assertEqual(value.hex(), 'a6bfac152f9071fbc21a73ca991a28898ec14f4df54c01cad49daf05d4012b4c')
        print(f'times_to_calculate: {times_to_calculate}')
        print(f'time_duration: {time_duration}')

    # @unittest.skip("a.i.")
    def test_get_storage_at(self):
        print("\nhttps://github.com/neonlabsorg/proxy-model.py/issues/289")
        value_to_store = 452356
        tx_store = self.storage_contract.functions.store(value_to_store).build_transaction()
        tx_store = self.proxy.sign_send_wait_transaction(self.eth_account, tx_store)
        print(f'tx_store: {tx_store}')

        number_pos = 0
        value_received = self.proxy.conn.get_storage_at(self.storage_contract.address, number_pos, "latest")["value"]
        print('eth_getStorageAt existing address and index => ', value_received.hex())
        self.assertEqual(int.from_bytes(value_received, byteorder='big'), value_to_store)

        non_existing_pos = 12
        value_received = self.proxy.conn.get_storage_at(self.storage_contract.address, non_existing_pos, "latest")["value"]
        print('eth_getStorageAt existing address and non-existing index => ', value_received.hex())
        self.assertEqual(int.from_bytes(value_received, byteorder='big'), 0)

        non_exising_address = b'\xe1\xda\xb7\xa6\x17\x6f\x87\x68\xF5\x3a\x42\x5f\x29\x61\x73\x60\x5e\xd5\x08\x32'
        value_received = self.proxy.conn.get_storage_at(non_exising_address, non_existing_pos, "latest")["value"]
        print('eth_getStorageAt non-existing address => ', value_received.hex())
        self.assertEqual(int.from_bytes(value_received, byteorder='big'), 0)

        not_a_contract_address = self.eth_account
        value_received = self.proxy.conn.get_storage_at(not_a_contract_address.address, 0, "latest")["value"]
        print('eth_getStorageAt not_a_contract_address address => ', value_received.hex())
        self.assertEqual(int.from_bytes(value_received, byteorder='big'), 0)

    # @unittest.skip("a.i.")
    def test_08_execute_with_huge_gas(self):
        print("\ntest_08_execute_with_huge_gas_limit")
        tx_store = self.storage_contract.functions.store(147).build_transaction({'gas': 987654321987654321})
        tx_store = self.proxy.sign_transaction(self.eth_account, tx_store)
        print(f'tx_store: {tx_store}')
        try:
            tx_store_hash = self.proxy.conn.send_raw_transaction(tx_store.tx_signed.rawTransaction)
            print('trx_store_hash:', tx_store_hash)
            self.assertTrue(False)
        except Exception as e:
            response = self.decode_error(e)
            self.assertEqual(response['code'], -32000)
            message = 'insufficient funds for gas * price + value'
            self.assertEqual(response['message'][:len(message)], message)

    # @unittest.skip("a.i.")
    def test_09_prior_eip_155(self):
        print("\ntest_09_prior_eip_155")

        eth_test_account = self.proxy.create_account('eth_test_account')
        print(f'eth_test_account.address: {eth_test_account.address}')

        balance_before_transfer = self.proxy.conn.get_balance(eth_test_account.address)
        print(f'balance_before_transfer: {balance_before_transfer}')

        print("transfer 1 GAlan to eth_test_account")
        tx_transfer = self.proxy.sign_send_wait_transaction(
            self.eth_account,
            dict(
                to=eth_test_account.address,
                value=eth_utils.denoms.gwei
            )
        )
        print(f'trx_transfer: {tx_transfer}')

        balance_after_transfer = self.proxy.conn.get_balance(eth_test_account.address)
        print(f'balance_after_transfer: {balance_after_transfer}')

        self.assertLessEqual(balance_after_transfer, balance_before_transfer + eth_utils.denoms.gwei)

    # @unittest.skip("a.i.")
    def test_10_transfer_not_enough_funds(self):
        print("\ntest_10_transfer_not_enough_funds")

        eth_account_alice = self.proxy.create_account('alice.whale')
        eth_account_bob = self.proxy.create_account('bob.carp')
        print('eth_account_alice.address:', eth_account_alice.address)
        print('eth_account_bob.address:', eth_account_bob.address)
        self.proxy.request_airdrop(eth_account_alice)

        tx_transfer = self.proxy.sign_transaction(
            eth_account_alice,
            dict(
                to=eth_account_bob.address,
                value=self.proxy.conn.get_balance(eth_account_alice.address) + 1
            )
        )
        print('trx_transfer:', tx_transfer)
        try:
            tx_transfer_hash = self.proxy.conn.send_raw_transaction(tx_transfer.tx_signed.rawTransaction)
            print('trx_transfer_hash:', tx_transfer_hash.hex())
            self.assertTrue(False)
        except Exception as e:
            response = self.decode_error(e)
            self.assertEqual(response['code'], -32000)
            message = 'insufficient funds for transfer'
            self.assertEqual(response['message'][:len(message)], message)


class TestDistributorContract(unittest.TestCase):
    WAITING_DISTRIBUTE_RECEIPT_TIMEOUT_SEC = 15
    WAITING_SET_ADDRESS_RECEIPT_TIMEOUT_SEC = 10

    def setUp(self) -> None:
        self.proxy = Proxy()
        signer = self.proxy.create_signer_account()
        self.contract = self.proxy.compile_and_deploy_from_file(
            signer, "./proxy/testing/solidity_contracts/NeonDistributor.sol"
        ).contract

    def test_distribute_tx_affects_multiple_accounts(self):
        signer = self.proxy.create_signer_account()
        wallets = self.generate_wallets()
        self._set_and_check_distributor_addresses(wallets, signer)

        distribute_value_fn = self.contract.functions.distribute_value()
        nonce = self.proxy.conn.get_transaction_count(signer.address)
        tx_built = distribute_value_fn.build_transaction({"nonce": nonce})
        tx_built["value"] = 12
        distribute_fn_msg = signer.sign_transaction(tx_built)
        tx_hash = self.proxy.conn.send_raw_transaction(distribute_fn_msg.rawTransaction)
        print(f"Send `distribute_value_fn()` tx with nonce: {nonce}, tx_hash: {tx_hash}")
        print(f"Wait for `distribute_value_fn` receipt by hash: {tx_hash.hex()}")
        tx_receipt = self.proxy.conn.wait_for_transaction_receipt(
            tx_hash,
            timeout=self.WAITING_DISTRIBUTE_RECEIPT_TIMEOUT_SEC
        )
        self.assertEqual(tx_receipt.status, 1)

    def _set_and_check_distributor_addresses(self, wallets, signer):
        nonce: int = 0
        prebuilt_txs = []

        for name, account in wallets.items():
            set_address_fn = self.contract.functions.set_address(name, bytes.fromhex(account.address[2:]))
            set_address_fn_tx_built = set_address_fn.build_transaction({"nonce": nonce})
            set_address_msg = signer.sign_transaction(set_address_fn_tx_built)
            nonce = nonce + 1
            prebuilt_txs.append((set_address_msg.rawTransaction, name, account))

        tx_hashes: List[TxReceipt] = []
        for prebuilt_tx in prebuilt_txs:
            raw_tx, name, account = prebuilt_tx
            tx_hash = self.proxy.conn.send_raw_transaction(raw_tx)
            print(
                f"Send `set_address_fn(\"{name}\", {account.address[2:]}` "
                f"tx with nonce: {nonce}, tx_hash: {tx_hash.hex()}"
            )
            tx_hashes.append(tx_hash)

        for tx_hash in tx_hashes:
            tx_receipt = self.proxy.conn.wait_for_transaction_receipt(
                tx_hash,
                timeout=self.WAITING_SET_ADDRESS_RECEIPT_TIMEOUT_SEC
            )
            self.assertEqual(tx_receipt.status, 1)

    def generate_wallets(self):
        names = [
            "alice", "bob", "carol", "dave", "erine", "eve", "frank",
            "mallory", "pat", "peggy", "trudy", "vanna", "victor"
        ]
        wallets = {name: self.proxy.create_account() for name in names}
        return wallets


class TestNonce(unittest.TestCase):
    TRANSFER_CNT = 25

    def setUp(self) -> None:
        self.proxy = Proxy()
        self.signer = self.proxy.create_signer_account()
        self.receiver = self.proxy.conn.account.create('nonce-receiver-25')

    def _send_transfer_tx(self, nonce: int) -> HexBytes:
        tx_transfer = self.proxy.sign_transaction(
            self.signer,
            dict(
                nonce=nonce,
                to=self.receiver.address,
                value=1
            )
        )
        return self.proxy.conn.send_raw_transaction(tx_transfer.tx_signed.rawTransaction)

    def _wait_tx_list(self, tx_hash_list: List[HexBytes]) -> None:
        for tx_hash in tx_hash_list:
            tx_receipt = self.proxy.conn.wait_for_transaction_receipt(tx_hash)
            self.assertEqual(tx_receipt.status, 1)

    def _get_base_nonce(self) -> int:
        return self.proxy.conn.get_transaction_count(self.signer.address, "pending")

    def test_get_receipt_sequence(self):
        tx_hash_list: List[HexBytes] = []
        for i in range(self.TRANSFER_CNT):
            nonce = self._get_base_nonce()
            tx_hash = self._send_transfer_tx(nonce)
            tx_hash_list.append(tx_hash)

        self._wait_tx_list(tx_hash_list)

    def test_mono_sequence(self):
        nonce = self._get_base_nonce()
        tx_hash_list: List[HexBytes] = []
        for i in range(self.TRANSFER_CNT):
            tx_hash = self._send_transfer_tx(nonce)
            tx_hash_list.append(tx_hash)
            nonce += 1

        self._wait_tx_list(tx_hash_list)

    def test_reverse_sequence(self):
        nonce = self._get_base_nonce()
        nonce_list: List[int] = []
        for i in range(self.TRANSFER_CNT):
            nonce_list.insert(0, nonce)
            nonce += 1

        tx_hash_list: List[HexBytes] = []
        for nonce in nonce_list:
            tx_hash = self._send_transfer_tx(nonce)
            tx_hash_list.append(tx_hash)

        self._wait_tx_list(tx_hash_list)

    def test_random_sequence(self):
        nonce = self._get_base_nonce()
        nonce_list: List[int] = []
        for i in range(self.TRANSFER_CNT):
            nonce_list.append(nonce)
            nonce += 1
        random.shuffle(nonce_list)

        tx_hash_list: List[HexBytes] = []
        for nonce in nonce_list:
            tx_hash = self._send_transfer_tx(nonce)
            tx_hash_list.append(tx_hash)
        self._wait_tx_list(tx_hash_list)


if __name__ == '__main__':
    unittest.main()
