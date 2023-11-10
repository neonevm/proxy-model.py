import unittest
import subprocess

from typing import Dict, Any

from web3 import eth as web3_eth

from proxy.common_neon.constants import EVM_PROGRAM_ID
from proxy.common_neon.config import Config
from proxy.common_neon.neon_instruction import NeonIxBuilder
from proxy.common_neon.solana_tx import SolAccountMeta, SolTxIx, SolPubKey, SolAccount
from proxy.common_neon.solana_tx_legacy import SolLegacyTx
from proxy.common_neon.utils.eth_proto import NeonTx
from proxy.common_neon.operator_resource_info import build_test_resource_info

from proxy.mempool.mempool_executor_task_op_res import OpResInit

from proxy.neon_core_api.neon_client import NeonClient

from proxy.testing.testing_helpers import Proxy, SolClient, NeonLocalAccount
from proxy.testing.solana_utils import WalletAccount, wallet_path


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


class CompleteTest(unittest.TestCase):
    proxy: Proxy
    chain_id: int
    config: FakeConfig
    neon_client: NeonClient
    solana: SolClient
    test_program_address: SolPubKey
    neon_account: NeonLocalAccount
    neon_account_invoked: NeonLocalAccount
    neon_account_getter: NeonLocalAccount
    signer: SolAccount
    storage_contract: web3_eth.Contract

    @classmethod
    def setUpClass(cls):
        print("\ntest_indexer_work.py setUpClass")

        cls.proxy = Proxy()
        cls.config = FakeConfig()
        cls.neon_account = cls.proxy.create_signer_account(SEED)
        cls.neon_account_invoked = cls.proxy.create_signer_account(SEED_INVOKED)
        cls.neon_account_getter = cls.proxy.create_signer_account(SEED_GETTER)
        cls.neon_client = NeonClient(cls.config)
        cls.solana = SolClient(cls.config)
        cls.chain_id = cls.proxy.web3.eth.chain_id
        cls.test_program_address = cls.get_test_program_name()

        print(f"proxy_program: {str(cls.test_program_address)}")

        wallet = WalletAccount(wallet_path())
        cls.signer = wallet.get_acc()

        deployed_info = cls.proxy.compile_and_deploy_contract(cls.neon_account, TEST_EVENT_SOURCE_196)
        cls.storage_contract = deployed_info.contract
        print(cls.storage_contract.address)

        cls.create_two_calls_in_transaction()
        cls.create_hanged_transaction()
        cls.create_invoked_transaction()
        cls.create_invoked_transaction_combined()

    @classmethod
    def get_test_program_name(cls) -> SolPubKey:
        pubkey = subprocess.check_output([
            'solana', 'address', '-k', '/spl/bin/neon_test_invoke_program-keypair.json'
        ])
        return SolPubKey.from_string(bytes.decode(pubkey, 'utf8').strip())

    @classmethod
    def create_neon_ix_builder(cls, raw_tx, emulate_res: Dict[str, Any]):
        resource = build_test_resource_info(
            cls.neon_client,
            private_key=cls.signer.secret(),
            res_id=int.from_bytes(raw_tx[:8], byteorder="little")
        )
        OpResInit(cls.config, cls.solana, cls.neon_client).init_resource(resource)

        neon_ix_builder = NeonIxBuilder(resource.public_key)
        neon_ix_builder.init_operator_neon(resource.neon_account_dict[cls.chain_id].solana_address)

        neon_tx = NeonTx.from_string(raw_tx)
        neon_ix_builder.init_neon_tx(neon_tx)

        neon_account_list = [
            SolAccountMeta(
                is_signer=False,
                is_writable=a['is_writable'],
                pubkey=SolPubKey.from_string(a['pubkey'])
            )
            for a in emulate_res.get('solana_accounts', list())
        ]
        neon_ix_builder.init_neon_account_list(neon_account_list)

        neon_ix_builder.init_iterative(resource.holder_account)

        return neon_ix_builder, resource.signer

    @classmethod
    def create_hanged_transaction(cls):
        print("\ncreate_hanged_transaction")
        tx_store = cls.storage_contract.functions.addReturnEventTwice(1, 1).build_transaction({
            'from': cls.neon_account.address,
            'gasPrice': 0
        })
        tx_store = cls.proxy.sign_transaction(cls.neon_account, tx_store)

        emulate_res = cls.proxy.emulate(tx_store.tx_signed.rawTransaction)
        print(f'emulate: {emulate_res}')

        neon_ix_builder, signer = cls.create_neon_ix_builder(tx_store.tx_signed.rawTransaction, emulate_res)

        cls.tx_hash = tx_hash = tx_store.tx_signed.hash
        print(f'tx_hash: {tx_hash.hex()}')

        tx = SolLegacyTx(
            name='HangedTx',
            ix_list=[
                neon_ix_builder.make_compute_budget_heap_ix(),
                neon_ix_builder.make_compute_budget_cu_ix(),
                neon_ix_builder.make_tx_step_from_data_ix(10, 1)
            ]
        )
        cls.solana.send_tx(tx, signer)

    @classmethod
    def create_invoked_transaction(cls):
        print("\ncreate_invoked_transaction")

        tx_transfer = cls.proxy.sign_transaction(
            cls.neon_account_invoked,
            dict(
                to=cls.neon_account_getter.address,
                value=1_000_000_000_000_000_000
            )
        )

        emulate_res = cls.proxy.emulate(tx_transfer.tx_signed.rawTransaction)
        print(f'emulate: {emulate_res}')

        cls.tx_hash_invoked = tx_hash = tx_transfer.tx_signed.hash
        print(f'tx_hash_invoked: {tx_hash.hex}')

        neon_ix_builder, signer = cls.create_neon_ix_builder(tx_transfer.tx_signed.rawTransaction, emulate_res)
        noniterative = neon_ix_builder.make_tx_exec_from_data_ix()

        tx = SolLegacyTx(
            name='InvokedTx',
            ix_list=[
                neon_ix_builder.make_compute_budget_heap_ix(),
                neon_ix_builder.make_compute_budget_cu_ix(),
                SolTxIx(
                    accounts=[
                        SolAccountMeta(pubkey=EVM_PROGRAM_ID, is_signer=False, is_writable=False)
                    ] + noniterative.accounts,
                    data=noniterative.data,
                    program_id=cls.test_program_address
                )
            ]
        )

        cls.solana.send_tx(tx, signer)

    @classmethod
    def create_invoked_transaction_combined(cls):
        print("\ncreate_invoked_transaction_combined")

        tx_transfer = cls.proxy.sign_transaction(
            cls.neon_account_invoked,
            dict(
                to=cls.neon_account_getter.address,
                value=500_000_000_000_000_000
            )
        )

        cls.tx_hash_invoked_combined = tx_hash = tx_transfer.tx_signed.hash
        print(f'tx_hash_invoked_combined: {tx_hash.hex()}')

        emulate_res = cls.proxy.emulate(tx_transfer.tx_signed.rawTransaction)
        print(f'emulate: {emulate_res}')

        neon_ix_builder, signer = cls.create_neon_ix_builder(tx_transfer.tx_signed.rawTransaction, emulate_res)

        iterative = neon_ix_builder.make_tx_step_from_data_ix(250, 1)
        tx = SolLegacyTx(
            name='InvokedCombineTx',
            ix_list=[
                neon_ix_builder.make_compute_budget_heap_ix(),
                neon_ix_builder.make_compute_budget_cu_ix(),
                SolTxIx(
                    accounts=[
                        SolAccountMeta(pubkey=EVM_PROGRAM_ID, is_signer=False, is_writable=False)
                    ] + iterative.accounts,
                    data=b''.join([bytes.fromhex("ef"), iterative.data]),
                    program_id=cls.test_program_address
                )
            ]
        )

        cls.solana.send_tx(tx, signer)

    @classmethod
    def create_two_calls_in_transaction(cls):
        print("\ncreate_two_calls_in_transaction")

        nonce1 = cls.proxy.conn.get_transaction_count(cls.neon_account.address)
        tx = {'nonce': nonce1, 'from': cls.neon_account.address}
        call1_dict = cls.storage_contract.functions.addReturn(1, 1).build_transaction(tx)
        call1 = cls.proxy.sign_transaction(cls.neon_account, call1_dict)

        cls.tx_hash_call1 = tx_hash = call1.tx_signed.hash
        print(f'tx_hash_call1: {tx_hash.hex()}')

        emulate_res1 = cls.proxy.emulate(call1.tx_signed.rawTransaction)
        print(f'emulate call1: {emulate_res1}')

        nonce2 = nonce1 + 1
        tx = {'nonce': nonce2, 'from': cls.neon_account.address}
        call2_dict = cls.storage_contract.functions.addReturnEvent(2, 2).build_transaction(tx)
        call2 = cls.proxy.sign_transaction(cls.neon_account, call2_dict)

        cls.tx_hash_call2 = tx_hash = call2.tx_signed.hash
        print(f'tx_hash_call2: {tx_hash.hex()}')

        emulate_res2 = cls.proxy.emulate(call2.tx_signed.rawTransaction)
        print(f'emulate call2: {emulate_res2}')

        neon_ix_builder, signer = cls.create_neon_ix_builder(call1.tx_signed.rawTransaction, emulate_res1)
        noniterative1 = neon_ix_builder.make_tx_exec_from_data_ix()

        neon_ix_builder.init_neon_tx(NeonTx.from_string(call2.tx_signed.rawTransaction))
        neon_ix_builder, signer = cls.create_neon_ix_builder(call2.tx_signed.rawTransaction, emulate_res2)
        noniterative2 = neon_ix_builder.make_tx_exec_from_data_ix()

        tx = SolLegacyTx(
            name='TwoCallsTx',
            ix_list=[
                neon_ix_builder.make_compute_budget_heap_ix(),
                neon_ix_builder.make_compute_budget_cu_ix(),
                noniterative1,
                noniterative2
            ]
        )

        cls.solana.send_tx(tx, signer)

    # @unittest.skip("a.i.")
    def test_01_completed(self):
        print("\ntest_01_completed")
        trx_receipt = self.proxy.conn.wait_for_transaction_receipt(self.tx_hash)
        print('trx_receipt:', trx_receipt)
        self.assertEqual(trx_receipt['status'], 1)

    # def test_02_get_code_from_indexer(self):
    #     print("\ntest_02_get_code_from_indexer")
    #     code = self.proxy.conn.get_code(self.storage_contract.address)
    #     print("getCode result:", code.hex())
    #     print("storage_contract.bytecode:", self.storage_contract.bytecode.hex())
    #     self.assertEqual(code, self.storage_contract.bytecode[-len(code):])
    #
    # def test_03_invoked_found(self):
    #     print("\ntest_03_invoked_found")
    #     trx_receipt = self.proxy.conn.wait_for_transaction_receipt(self.tx_hash_invoked)
    #     print('trx_receipt:', trx_receipt)

    def test_04_right_result_for_invoked(self):
        print("\ntest_04_right_result_for_invoked")
        trx_receipt = self.proxy.conn.wait_for_transaction_receipt(self.tx_hash_invoked_combined)
        print('trx_receipt:', trx_receipt)

    # def test_05_check_two_calls_in_transaction(self):
    #     print("\ntest_05_check_two_calls_in_transaction")
    #     call1_receipt = self.proxy.conn.wait_for_transaction_receipt(self.tx_hash_call1)
    #     print('test_05 receipt1:', call1_receipt)
    #     self.assertEqual(len(call1_receipt['logs']), 0)
    #     call2_receipt = self.proxy.conn.wait_for_transaction_receipt(self.tx_hash_call2)
    #     print('test_05 receipt2:', call2_receipt)
    #     self.assertEqual(len(call2_receipt['logs']), 1)


if __name__ == '__main__':
    unittest.main()
