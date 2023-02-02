import unittest
import os

from solana.rpc.api import Client as SolanaClient
from .solana_utils import WalletAccount, wallet_path, EvmLoader, client, send_transaction

from proxy.common_neon.environment_data import EVM_LOADER_ID
from proxy.common_neon.address import NeonAddress
from proxy.common_neon.config import Config
from proxy.common_neon.neon_instruction import NeonIxBuilder
from proxy.common_neon.solana_tx import SolAccountMeta, SolTxIx, SolPubKey
from proxy.common_neon.solana_tx_legacy import SolLegacyTx
from proxy.common_neon.solana_interactor import SolInteractor
from proxy.common_neon.eth_proto import NeonTx
from proxy.mempool.operator_resource_mng import OpResInfo, OpResInit, OpResIdent

from proxy.testing.testing_helpers import Proxy


proxy_program = os.environ.get("TEST_PROGRAM")

SEED = 'https://github.com/neonlabsorg/proxy-model.py/issues/196'
SEED_INVOKED = 'https://github.com/neonlabsorg/proxy-model.py/issues/755'
SEED_GETTER = SEED + "/GETTER"


TEST_EVENT_SOURCE_196 = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.5.12;

contract ReturnsEvents {
    event Added(uint8 sum);

    function addNoReturn(uint8 x, uint8 y) public {
        x + y;
    }

    function addReturn(uint8 x, uint8 y) public returns(uint8) {
        return x + y;
    }

    function addReturnEvent(uint8 x, uint8 y) public returns(uint8) {
        uint8 sum =x+y;

        emit Added(sum);
        return sum;
    }

    function addReturnEventTwice(uint8 x, uint8 y) public returns(uint8) {
        uint8 sum = x + y;
        emit Added(sum);
        sum += y;
        emit Added(sum);
        return sum;
    }
}
'''


class FakeConfig(Config):
    @property
    def min_operator_balance_to_warn(self) -> int:
        return 1

    @property
    def min_operator_balance_to_err(self) -> int:
        return 1


class CancelTest(unittest.TestCase):
    proxy: Proxy

    @classmethod
    def setUpClass(cls):
        print("\ntest_indexer_work.py setUpClass")

        cls.proxy = proxy = Proxy()
        cls.eth_account = eth_account = cls.proxy.create_signer_account(SEED)
        cls.eth_account_invoked = eth_account_invoked = cls.proxy.create_signer_account(SEED_INVOKED)
        cls.eth_account_getter = eth_account_getter = cls.proxy.create_signer_account(SEED_GETTER)

        cls.solana = SolanaClient(Config().solana_url)

        print(f"proxy_program: {proxy_program}")

        wallet = WalletAccount(wallet_path())
        cls.loader = loader = EvmLoader(wallet, EVM_LOADER_ID)
        cls.signer = wallet.get_acc()

        deployed_info = proxy.compile_and_deploy_contract(eth_account, TEST_EVENT_SOURCE_196)
        cls.storage_contract = storage_contract = deployed_info.contract
        print(storage_contract.address)

        reid_eth = storage_contract.address.lower()
        print('contract_eth', reid_eth)
        cls.re_id, _ = re_id, _ = loader.ether2program(str(reid_eth))
        print('contract', re_id)

        # Create ethereum account for user account
        cls.caller_ether = caller_ether = NeonAddress.from_private_key(bytes(eth_account.key))
        cls.caller, _ = caller, _ = loader.ether2program(str(caller_ether))

        cls.caller_ether_invoked = caller_ether_invoked = NeonAddress.from_private_key(bytes(eth_account_invoked.key))
        cls.caller_invoked, _ = caller_invoked, _ = loader.ether2program(str(caller_ether_invoked))

        cls.caller_ether_getter = caller_ether_getter = NeonAddress.from_private_key(bytes(eth_account_getter.key))
        cls.caller_getter, _ = caller_getter, _ = loader.ether2program(str(caller_ether_getter))

        print(f'caller_ether: {caller_ether} {caller}')
        print(f'caller_ether_invoked: {caller_ether_invoked} {caller_invoked}')
        print(f'caller_ether_getter: {caller_ether_getter} {caller_getter}')

        cls.create_two_calls_in_transaction(cls)
        cls.create_hanged_transaction(cls)
        cls.create_invoked_transaction(cls)
        cls.create_invoked_transaction_combined(cls)

    def create_neon_ix_builder(self, raw_tx, neon_account_list):
        resource = OpResInfo.from_ident(OpResIdent(
            public_key=str(self.signer.pubkey()),
            private_key=self.signer.secret(),
            res_id=int.from_bytes(raw_tx[:8], byteorder="little")
        ))
        config = FakeConfig()
        OpResInit(config, SolInteractor(config, config.solana_url)).init_resource(resource)

        neon_ix_builder = NeonIxBuilder(resource.public_key)
        neon_ix_builder.init_operator_neon(NeonAddress.from_private_key(resource.secret_key))

        neon_tx = NeonTx.from_string(raw_tx)
        neon_ix_builder.init_neon_tx(neon_tx)
        neon_ix_builder.init_neon_account_list(neon_account_list)

        neon_ix_builder.init_iterative(resource.holder)

        return neon_ix_builder, resource.signer

    @staticmethod
    def print_if_err(receipt):
        if not isinstance(receipt, dict):
            return
        if receipt.get('result', None) is None:
            return
        if receipt.get('result').get('meta', None) is None:
            return
        if receipt.get('result').get('meta').get('err') is None:
            return
        print(f"{receipt}")

    def create_hanged_transaction(self):
        print("\ncreate_hanged_transaction")
        tx_store = self.storage_contract.functions.addReturnEventTwice(1, 1).build_transaction({
            'from': self.eth_account.address,
            'gasPrice': 0
        })
        tx_store = self.proxy.sign_transaction(self.eth_account, tx_store)

        neon_ix_builder, signer = self.create_neon_ix_builder(
            self,
            tx_store.tx_signed.rawTransaction,
            [
                SolAccountMeta(pubkey=self.re_id, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self.caller, is_signer=False, is_writable=True)
            ]
        )

        self.tx_hash = tx_hash = tx_store.tx_signed.hash
        print(f'tx_hash: {tx_hash.hex()}')

        tx = SolLegacyTx(instructions=[
            neon_ix_builder.make_compute_budget_heap_ix(),
            neon_ix_builder.make_compute_budget_cu_ix(),
            neon_ix_builder.make_tx_step_from_data_ix(10, 1)
        ])
        receipt = send_transaction(client, tx.low_level_tx, signer)
        self.print_if_err(receipt)

    def create_invoked_transaction(self):
        print("\ncreate_invoked_transaction")

        tx_transfer = self.proxy.sign_transaction(
            self.eth_account_invoked,
            dict(
                to=self.eth_account_getter.address,
                value=1_000_000_000_000_000_000
            )
        )

        self.tx_hash_invoked = tx_hash = tx_transfer.tx_signed.hash
        print(f'tx_hash_invoked: {tx_hash.hex}')

        neon_ix_builder, signer = self.create_neon_ix_builder(
            self,
            tx_transfer.tx_signed.rawTransaction,
            [
                SolAccountMeta(pubkey=self.caller_getter, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self.caller_invoked, is_signer=False, is_writable=True)
            ]
        )
        noniterative = neon_ix_builder.make_tx_exec_from_data_ix()

        tx = SolLegacyTx(instructions=[
            neon_ix_builder.make_compute_budget_heap_ix(),
            neon_ix_builder.make_compute_budget_cu_ix(),
            SolTxIx(
                accounts=[SolAccountMeta(pubkey=SolPubKey.from_string(EVM_LOADER_ID), is_signer=False, is_writable=False)] +
                     noniterative.accounts,
                data=noniterative.data,
                program_id=SolPubKey.from_string(proxy_program)
            )
        ])

        receipt = send_transaction(client, tx.low_level_tx, signer)
        self.print_if_err(receipt)

    def create_invoked_transaction_combined(self):
        print("\ncreate_invoked_transaction_combined")

        tx_transfer = self.proxy.sign_transaction(
            self.eth_account_invoked,
            dict(
                to=self.eth_account_getter.address,
                value=500_000_000_000_000_000
            )
        )

        self.tx_hash_invoked_combined = tx_hash = tx_transfer.tx_signed.hash
        print(f'tx_hash_invoked_combined: {tx_hash.hex()}')

        neon_ix_builder, signer = self.create_neon_ix_builder(
            self,
            tx_transfer.tx_signed.rawTransaction,
            [
                SolAccountMeta(pubkey=self.caller_getter, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=self.caller_invoked, is_signer=False, is_writable=True),
            ]
        )

        iterative = neon_ix_builder.make_tx_step_from_data_ix(250, 1)
        tx = SolLegacyTx(instructions=[
            neon_ix_builder.make_compute_budget_heap_ix(),
            neon_ix_builder.make_compute_budget_cu_ix(),
            SolTxIx(
                accounts=[SolAccountMeta(pubkey=SolPubKey.from_string(EVM_LOADER_ID), is_signer=False, is_writable=False)] +
                     iterative.accounts,
                data=b''.join([bytes.fromhex("ef"), iterative.data]),
                program_id=SolPubKey.from_string(proxy_program)
            )
        ])

        receipt = send_transaction(client, tx.low_level_tx, signer)
        self.print_if_err(receipt)

    def create_two_calls_in_transaction(self):
        print("\ncreate_two_calls_in_transaction")

        account_list = [
            SolAccountMeta(pubkey=self.caller, is_signer=False, is_writable=True),
            SolAccountMeta(pubkey=self.re_id, is_signer=False, is_writable=True),
        ]

        nonce1 = self.proxy.conn.get_transaction_count(self.eth_account.address)
        tx = {'nonce': nonce1, 'from': self.eth_account.address}
        call1_dict = self.storage_contract.functions.addReturn(1, 1).build_transaction(tx)
        call1 = self.proxy.sign_transaction(self.eth_account, call1_dict)

        self.tx_hash_call1 = tx_hash = call1.tx_signed.hash
        print(f'tx_hash_call1: {tx_hash.hex()}')

        nonce2 = nonce1 + 1
        tx = {'nonce': nonce2, 'from': self.eth_account.address}
        call2_dict = self.storage_contract.functions.addReturnEvent(2, 2).build_transaction(tx)
        call2 = self.proxy.sign_transaction(self.eth_account, call2_dict)

        self.tx_hash_call2 = tx_hash = call2.tx_signed.hash
        print(f'tx_hash_call2: {tx_hash.hex()}')

        neon_ix_builder, signer = self.create_neon_ix_builder(self, call1.tx_signed.rawTransaction, account_list)
        noniterative1 = neon_ix_builder.make_tx_exec_from_data_ix()

        neon_ix_builder.init_neon_tx(NeonTx.from_string(call2.tx_signed.rawTransaction))
        noniterative2 = neon_ix_builder.make_tx_exec_from_data_ix()

        tx = SolLegacyTx(instructions=[
            neon_ix_builder.make_compute_budget_heap_ix(),
            neon_ix_builder.make_compute_budget_cu_ix(),
            noniterative1,
            noniterative2
        ])

        receipt = send_transaction(client, tx.low_level_tx, signer)
        self.print_if_err(receipt)

    # @unittest.skip("a.i.")
    def test_01_canceled(self):
        print("\ntest_01_canceled")
        trx_receipt = self.proxy.conn.wait_for_transaction_receipt(self.tx_hash)
        print('trx_receipt:', trx_receipt)
        self.assertEqual(trx_receipt['status'], 0)

    def test_02_get_code_from_indexer(self):
        print("\ntest_02_get_code_from_indexer")
        code = self.proxy.conn.get_code(self.storage_contract.address)
        print("getCode result:", code.hex())
        print("storage_contract.bytecode:", self.storage_contract.bytecode.hex())
        self.assertEqual(code, self.storage_contract.bytecode[-len(code):])

    def test_03_invoked_found(self):
        print("\ntest_03_invoked_found")
        trx_receipt = self.proxy.conn.wait_for_transaction_receipt(self.tx_hash_invoked)
        print('trx_receipt:', trx_receipt)

    def test_04_right_result_for_invoked(self):
        print("\ntest_04_right_result_for_invoked")
        trx_receipt = self.proxy.conn.wait_for_transaction_receipt(self.tx_hash_invoked_combined)
        print('trx_receipt:', trx_receipt)

    def test_05_check_two_calls_in_transaction(self):
        print("\ntest_05_check_two_calls_in_transaction")
        call1_receipt = self.proxy.conn.wait_for_transaction_receipt(self.tx_hash_call1)
        print('test_05 receipt1:', call1_receipt)
        self.assertEqual(len(call1_receipt['logs']), 0)
        call2_receipt = self.proxy.conn.wait_for_transaction_receipt(self.tx_hash_call2)
        print('test_05 receipt2:', call2_receipt)
        self.assertEqual(len(call2_receipt['logs']), 1)


if __name__ == '__main__':
    unittest.main()
