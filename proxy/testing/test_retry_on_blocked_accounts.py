import datetime
import multiprocessing
import unittest
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.eth_proto import NeonTx
from ..common_neon.address import EthereumAddress
from ..common_neon.config import Config
from ..common_neon.solana_interactor import SolInteractor
from ..mempool.operator_resource_mng import OpResInfo, OpResInit
from .solana_utils import *
from web3 import Web3
from .testing_helpers import request_airdrop
from solcx import compile_source


SEED = 'https://github.com/neonlabsorg/proxy-model.py/issues/365'
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
eth_account = proxy.eth.account.create(SEED)
proxy.eth.default_account = eth_account.address

TEST_RETRY_BLOCKED_365 = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.5.12;

contract BlockForAWhile {
    uint32 counter = 0;

    function add_some(uint32 some, uint32 loop, string memory _padding) public {
        for(uint32 i = 0; i < loop; i++){
            counter += some + i;
        }
    }
}
'''


def send_routine(acc_seed, contract_address, abi, loop, return_dict, padding_string):
    print("Send parallel transaction from {}".format(acc_seed))
    print(datetime.datetime.now().time())
    storage_contract = proxy.eth.contract(
            address=contract_address,
            abi=abi
        )
    new_eth_account = proxy.eth.account.create(acc_seed)
    request_airdrop(new_eth_account.address)
    right_nonce = proxy.eth.get_transaction_count(new_eth_account.address)
    tx_store = storage_contract.functions.add_some(2, loop, padding_string).buildTransaction(
        {
            "chainId": proxy.eth.chain_id,
            "gas": 987654321,
            "gasPrice": proxy.eth.gas_price,
            "nonce": right_nonce,
        }
    )
    tx_store_signed = proxy.eth.account.sign_transaction(tx_store, new_eth_account.key)
    tx_store_hash = proxy.eth.send_raw_transaction(tx_store_signed.rawTransaction)
    tx_store_receipt = proxy.eth.wait_for_transaction_receipt(tx_store_hash)
    return_dict[acc_seed] = tx_store_receipt


class FakeConfig(Config):
    @property
    def min_operator_balance_to_warn(self) -> int:
        return 1

    @property
    def min_operator_balance_to_err(self) -> int:
        return 1


class BlockedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\ntest_retry_on_blocked_accounts.py setUpClass")
        request_airdrop(eth_account.address)

        wallet = WalletAccount(wallet_path())
        cls.loader = loader = EvmLoader(wallet, EVM_LOADER)

        cls.solana = solana = SolInteractor(Config(), solana_url)

        cls.resource_iter = resource = OpResInfo(wallet.get_acc(), 365)
        OpResInit(FakeConfig(), solana).init_resource(resource)

        cls.resource_single = resource = OpResInfo(wallet.get_acc(), 366)
        OpResInit(FakeConfig(), solana).init_resource(resource)

        tx_deploy_receipt, storage = cls.deploy_contract()
        cls.contractAddress = tx_deploy_receipt.contractAddress
        cls.abi = storage.abi

        storage_contract = proxy.eth.contract(
            address=tx_deploy_receipt.contractAddress,
            abi=storage.abi
        )
        cls.storage_contract = storage_contract

        print(storage_contract.address)

        reid_eth = storage_contract.address.lower()
        print('contract_eth', reid_eth)
        cls.re_id, _ = re_id, _ = loader.ether2program(reid_eth)
        print('contract', re_id)

        cls.caller, _ = loader.ether2program(proxy.eth.default_account)

    @staticmethod
    def deploy_contract():
        compiled_sol = compile_source(TEST_RETRY_BLOCKED_365)
        contract_id, contract_interface = compiled_sol.popitem()
        storage = proxy.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        tx_deploy = proxy.eth.account.sign_transaction(
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
        tx_deploy_hash = proxy.eth.send_raw_transaction(tx_deploy.rawTransaction)
        print('tx_deploy_hash:', tx_deploy_hash.hex())
        tx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        print('tx_deploy_receipt:', tx_deploy_receipt)

        return tx_deploy_receipt, storage

    def create_blocked_transaction(self, resource):
        print("\ncreate_blocked_transaction")
        right_nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx_store = self.storage_contract.functions.add_some(1, 30, "").buildTransaction({
            'nonce': right_nonce,
            'gasPrice': proxy.eth.gas_price
        })
        tx_store_signed = proxy.eth.account.sign_transaction(tx_store, eth_account.key)
        print(f'blocked tx hash: {tx_store_signed.hash.hex()}')

        neon_ix_builder = NeonIxBuilder(resource.public_key)
        neon_ix_builder.init_operator_neon(EthereumAddress.from_private_key(resource.secret_key))

        neon_tx = NeonTx.fromString(tx_store_signed.rawTransaction)
        neon_ix_builder.init_neon_tx(neon_tx)
        neon_ix_builder.init_neon_account_list([
            AccountMeta(pubkey=self.re_id, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.caller, is_signer=False, is_writable=True)
        ])

        neon_ix_builder.init_iterative(resource.holder)

        solana_tx = Transaction().add(
            neon_ix_builder.make_compute_budget_heap_ix(),
            neon_ix_builder.make_compute_budget_cu_ix(),
            neon_ix_builder.make_tx_step_from_data_ix(500, 1)
        )
        send_transaction(client, solana_tx, resource.signer)
        return solana_tx

    @staticmethod
    def finish_blocker_transaction(solana_tx, resource):
        return send_transaction(client, solana_tx, resource.signer)

    def test_blocked_iterative(self):
        print("\ntest_blocked_iterative")
        solana_tx = self.create_blocked_transaction(self.resource_iter)
        caller_seed = "long"
        manager = multiprocessing.Manager()
        return_dict = manager.dict()
        p2 = multiprocessing.Process(
            target=send_routine,
            args=(
                caller_seed, self.contractAddress, self.abi, 50, return_dict,
                """
                1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
                1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
                1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
                1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
                1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
                1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
                1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
                1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
                1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
                1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
                """))
        p2.start()
        self.finish_blocker_transaction(solana_tx, self.resource_iter)
        p2.join()
        print('test_blocked_iterative return_dict:', return_dict)
        self.assertEqual(return_dict[caller_seed]['status'], 1)

    def test_blocked_single(self):
        print("\ntest_blocked_single")
        solana_tx = self.create_blocked_transaction(self.resource_single)
        caller_seed = "short"
        manager = multiprocessing.Manager()
        return_dict = manager.dict()
        p2 = multiprocessing.Process(
            target=send_routine,
            args=(caller_seed, self.contractAddress, self.abi, 10, return_dict, ""))
        p2.start()
        self.finish_blocker_transaction(solana_tx, self.resource_single)
        p2.join()
        print('test_blocked_single return_dict:', return_dict)
        self.assertEqual(return_dict[caller_seed]['status'], 1)


if __name__ == '__main__':
    unittest.main()
