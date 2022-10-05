import unittest
import os
import base58

from solana.rpc.api import Client as SolanaClient
from .solana_utils import WalletAccount, wallet_path, EvmLoader, client, send_transaction

from solcx import compile_source
from web3 import Web3

from ..common_neon.environment_data import EVM_LOADER_ID
from ..common_neon.address import EthereumAddress
from ..common_neon.config import Config
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_transaction import SolAccountMeta, SolLegacyTx, SolTxIx, SolPubKey
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.eth_proto import NeonTx
from ..mempool.operator_resource_mng import OpResInfo, OpResInit

from .testing_helpers import request_airdrop


proxy_program = os.environ.get("TEST_PROGRAM")

SEED = 'https://github.com/neonlabsorg/proxy-model.py/issues/196'
SEED_INVOKED = 'https://github.com/neonlabsorg/proxy-model.py/issues/755'
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
eth_account = proxy.eth.account.create(SEED)
eth_account_invoked = proxy.eth.account.create(SEED_INVOKED)
eth_account_getter = proxy.eth.account.create("GETTER")
proxy.eth.default_account = eth_account.address

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
    @classmethod
    def setUpClass(cls):
        print("\ntest_indexer_work.py setUpClass")

        cls.solana = SolanaClient(Config().solana_url)

        request_airdrop(eth_account.address)
        request_airdrop(eth_account_invoked.address)
        request_airdrop(eth_account_getter.address)

        print(f"proxy_program: {proxy_program}")

        wallet = WalletAccount(wallet_path())
        cls.loader = loader = EvmLoader(wallet, EVM_LOADER_ID)
        cls.signer = wallet.get_acc()

        tx_deploy_receipt, storage = cls.deploy_contract()
        cls.storage_contract = storage_contract = proxy.eth.contract(
            address=tx_deploy_receipt.contractAddress,
            abi=storage.abi,
            bytecode=storage.bytecode
        )
        print(storage_contract.address)

        reid_eth = storage_contract.address.lower()
        print('contract_eth', reid_eth)
        cls.re_id, _ = re_id, _ = loader.ether2program(str(reid_eth))
        print('contract', re_id)

        # Create ethereum account for user account
        cls.caller_ether = caller_ether = EthereumAddress.from_private_key(bytes(eth_account.key))
        cls.caller, _ = caller, _ = loader.ether2program(str(caller_ether))

        cls.caller_ether_invoked = caller_ether_invoked = EthereumAddress.from_private_key(bytes(eth_account_invoked.key))
        cls.caller_invoked, _ = caller_invoked, _ = loader.ether2program(str(caller_ether_invoked))

        cls.caller_ether_getter = caller_ether_getter = EthereumAddress.from_private_key(bytes(eth_account_getter.key))
        cls.caller_getter, _ = caller_getter, _ = loader.ether2program(str(caller_ether_getter))

        print(f'caller_ether: {caller_ether} {caller}')
        print(f'caller_ether_invoked: {caller_ether_invoked} {caller_invoked}')
        print(f'caller_ether_getter: {caller_ether_getter} {caller_getter}')

        cls.create_two_calls_in_transaction()
        cls.create_hanged_transaction()
        cls.create_invoked_transaction()
        cls.create_invoked_transaction_combined()

    @staticmethod
    def deploy_contract():
        compiled_sol = compile_source(TEST_EVENT_SOURCE_196)
        _, contract_interface = compiled_sol.popitem()
        storage = proxy.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        trx_deploy = proxy.eth.account.sign_transaction(
            dict(
                nonce=proxy.eth.get_transaction_count(proxy.eth.default_account),
                chainId=proxy.eth.chain_id,
                gas=987654321,
                gasPrice=proxy.eth.gas_price,
                to='',
                value=0,
                data=storage.bytecode
            ),
            eth_account.key
        )
        tx_deploy_hash = proxy.eth.send_raw_transaction(trx_deploy.rawTransaction)
        print('trx_deploy_hash:', tx_deploy_hash.hex())
        tx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        print('trx_deploy_receipt:', tx_deploy_receipt)

        return tx_deploy_receipt, storage

    @classmethod
    def create_neon_ix_builder(cls, raw_tx, neon_account_list):
        resource = OpResInfo(cls.signer, int.from_bytes(raw_tx[:8], byteorder="little"))
        config = FakeConfig()
        OpResInit(config, SolInteractor(config, config.solana_url)).init_resource(resource)

        neon_ix_builder = NeonIxBuilder(resource.public_key)
        neon_ix_builder.init_operator_neon(EthereumAddress.from_private_key(resource.secret_key))

        neon_tx = NeonTx.fromString(raw_tx)
        neon_ix_builder.init_neon_tx(neon_tx)
        neon_ix_builder.init_neon_account_list(neon_account_list)

        neon_ix_builder.init_iterative(resource.holder)

        return neon_ix_builder, resource.signer

    @staticmethod
    def print_tx(tx):
        print(tx.__dict__)
        print(f'invoke signature: {base58.b58encode(tx.signature()).decode("utf-8")}')

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

    @classmethod
    def create_hanged_transaction(cls):
        print("\ncreate_hanged_transaction")
        right_nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx_store = cls.storage_contract.functions.addReturnEventTwice(1, 1).buildTransaction({
            'nonce': right_nonce,
            'gasPrice': proxy.eth.gas_price
        })
        tx_store_signed = proxy.eth.account.sign_transaction(tx_store, eth_account.key)

        neon_ix_builder, signer = cls.create_neon_ix_builder(
            tx_store_signed.rawTransaction,
            [
                SolAccountMeta(pubkey=cls.re_id, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=cls.caller, is_signer=False, is_writable=True)
            ]
        )

        cls.tx_hash = tx_hash = tx_store_signed.hash
        print(f'tx_hash: {tx_hash.hex()}')

        tx = SolLegacyTx().add(
            neon_ix_builder.make_compute_budget_heap_ix(),
            neon_ix_builder.make_compute_budget_cu_ix(),
            neon_ix_builder.make_tx_step_from_data_ix(10, 1)
        )
        receipt = send_transaction(client, tx, signer)
        cls.print_tx(tx)
        cls.print_if_err(receipt)

    @classmethod
    def create_invoked_transaction(cls):
        print("\ncreate_invoked_transaction")

        tx_transfer_signed = proxy.eth.account.sign_transaction(
            dict(
                nonce=proxy.eth.get_transaction_count(eth_account_invoked.address),
                chainId=proxy.eth.chain_id,
                gas=987654321,
                gasPrice=proxy.eth.gas_price,
                to=eth_account_getter.address,
                value=1_000_000_000_000_000_000
            ),
            eth_account_invoked.key
        )

        cls.tx_hash_invoked = tx_hash = tx_transfer_signed.hash
        print(f'tx_hash_invoked: {tx_hash.hex}')

        neon_ix_builder, signer = cls.create_neon_ix_builder(
            tx_transfer_signed.rawTransaction,
            [
                SolAccountMeta(pubkey=cls.caller_getter, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=cls.caller_invoked, is_signer=False, is_writable=True)
            ]
        )
        noniterative = neon_ix_builder.make_tx_exec_from_data_ix()

        tx = SolLegacyTx().add(
            neon_ix_builder.make_compute_budget_heap_ix(),
            neon_ix_builder.make_compute_budget_cu_ix(),
            SolTxIx(
                keys=[SolAccountMeta(pubkey=EVM_LOADER_ID, is_signer=False, is_writable=False)] + noniterative.keys,
                data=noniterative.data,
                program_id=SolPubKey(proxy_program)
            )
        )

        receipt = send_transaction(client, tx, signer)
        cls.print_tx(tx)
        cls.print_if_err(receipt)

    @classmethod
    def create_invoked_transaction_combined(cls):
        print("\ncreate_invoked_transaction_combined")

        tx_transfer_signed = proxy.eth.account.sign_transaction(
            dict(
                nonce=proxy.eth.get_transaction_count(eth_account_invoked.address),
                chainId=proxy.eth.chain_id,
                gas=987654321,
                gasPrice=proxy.eth.gas_price,
                to=eth_account_getter.address,
                value=500_000_000_000_000_000
            ),
            eth_account_invoked.key
        )

        cls.tx_hash_invoked_combined = tx_hash = tx_transfer_signed.hash
        print(f'tx_hash_invoked_combined: {tx_hash.hex()}')

        neon_ix_builder, signer = cls.create_neon_ix_builder(
            tx_transfer_signed.rawTransaction,
            [
                SolAccountMeta(pubkey=cls.caller_getter, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=cls.caller_invoked, is_signer=False, is_writable=True),
            ]
        )

        iterative = neon_ix_builder.make_tx_step_from_data_ix(250, 1)
        tx = SolLegacyTx().add(
            neon_ix_builder.make_compute_budget_heap_ix(),
            neon_ix_builder.make_compute_budget_cu_ix(),
            SolTxIx(
                keys=[SolAccountMeta(pubkey=EVM_LOADER_ID, is_signer=False, is_writable=False)] + iterative.keys,
                data=bytearray.fromhex("ef") + iterative.data,
                program_id=SolPubKey(proxy_program)
            )
        )

        receipt = send_transaction(client, tx, signer)
        cls.print_tx(tx)
        cls.print_if_err(receipt)

    @classmethod
    def create_two_calls_in_transaction(cls):
        print("\ncreate_two_calls_in_transaction")

        account_list = [
            SolAccountMeta(pubkey=cls.caller, is_signer=False, is_writable=True),
            SolAccountMeta(pubkey=cls.re_id, is_signer=False, is_writable=True),
        ]

        nonce1 = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx = {'nonce': nonce1, 'gasPrice': proxy.eth.gas_price}
        call1_dict = cls.storage_contract.functions.addReturn(1, 1).buildTransaction(tx)
        call1_signed = proxy.eth.account.sign_transaction(call1_dict, eth_account.key)

        cls.tx_hash_call1 = tx_hash = call1_signed.hash
        print(f'tx_hash_call1: {tx_hash.hex()}')

        nonce2 = nonce1 + 1
        tx = {'nonce': nonce2, 'gasPrice': proxy.eth.gas_price}
        call2_dict = cls.storage_contract.functions.addReturnEvent(2, 2).buildTransaction(tx)
        call2_signed = proxy.eth.account.sign_transaction(call2_dict, eth_account.key)

        cls.tx_hash_call2 = tx_hash = call2_signed.hash
        print(f'tx_hash_call2: {tx_hash.hex()}')

        neon_ix_builder, signer = cls.create_neon_ix_builder(call1_signed.rawTransaction, account_list)
        noniterative1 = neon_ix_builder.make_tx_exec_from_data_ix()

        neon_ix_builder.init_neon_tx(NeonTx.fromString(call2_signed.rawTransaction))
        noniterative2 = neon_ix_builder.make_tx_exec_from_data_ix()

        tx = SolLegacyTx().add(
            neon_ix_builder.make_compute_budget_heap_ix(),
            neon_ix_builder.make_compute_budget_cu_ix(),
            noniterative1,
            noniterative2
        )

        receipt = send_transaction(client, tx, signer)
        cls.print_tx(tx)
        cls.print_if_err(receipt)

    # @unittest.skip("a.i.")
    def test_01_canceled(self):
        print("\ntest_01_canceled")
        trx_receipt = proxy.eth.wait_for_transaction_receipt(self.tx_hash)
        print('trx_receipt:', trx_receipt)
        self.assertEqual(trx_receipt['status'], 0)

    def test_02_get_code_from_indexer(self):
        print("\ntest_02_get_code_from_indexer")
        code = proxy.eth.get_code(self.storage_contract.address)
        print("getCode result:", code.hex())
        print("storage_contract.bytecode:", self.storage_contract.bytecode.hex())
        self.assertEqual(code, self.storage_contract.bytecode[-len(code):])

    def test_03_invoked_found(self):
        print("\ntest_03_invoked_found")
        trx_receipt = proxy.eth.wait_for_transaction_receipt(self.tx_hash_invoked)
        print('trx_receipt:', trx_receipt)

    def test_04_right_result_for_invoked(self):
        print("\ntest_04_right_result_for_invoked")
        trx_receipt = proxy.eth.wait_for_transaction_receipt(self.tx_hash_invoked_combined)
        print('trx_receipt:', trx_receipt)

    def test_05_check_two_calls_in_transaction(self):
        print("\ntest_05_check_two_calls_in_transaction")
        call1_receipt = proxy.eth.wait_for_transaction_receipt(self.tx_hash_call1)
        print('test_05 receipt1:', call1_receipt)
        self.assertEqual(len(call1_receipt['logs']), 0)
        call2_receipt = proxy.eth.wait_for_transaction_receipt(self.tx_hash_call2)
        print('test_05 receipt2:', call2_receipt)
        self.assertEqual(len(call2_receipt['logs']), 1)


if __name__ == '__main__':
    unittest.main()
