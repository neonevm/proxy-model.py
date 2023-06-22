import unittest
import random
from typing import List

from .testing_helpers import Proxy, TxReceipt, HexBytes


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
            nonce += 1
            prebuilt_txs.append((set_address_msg.rawTransaction, name, account))

        tx_hashes: List[TxReceipt] = []
        for prebuilt_tx in prebuilt_txs:
            raw_tx, name, account = prebuilt_tx
            tx_hash = self.proxy.conn.send_raw_transaction(raw_tx)
            print(
                f"Send `set_address_fn(\"{name}\", {account.address[2:]}`) "
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
