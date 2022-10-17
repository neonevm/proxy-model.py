import datetime
import multiprocessing
import unittest
from proxy.common_neon.neon_instruction import NeonIxBuilder
from proxy.common_neon.eth_proto import NeonTx
from proxy.common_neon.address import NeonAddress
from proxy.common_neon.config import Config
from proxy.common_neon.solana_interactor import SolInteractor
from proxy.common_neon.solana_tx import SolAccountMeta
from proxy.common_neon.solana_tx_legacy import SolLegacyTx
from proxy.mempool.operator_resource_mng import OpResInfo, OpResInit
from proxy.testing.solana_utils import EVM_LOADER, EvmLoader, wallet_path, WalletAccount, client, send_transaction
from proxy.testing.testing_helpers import Proxy


SEED = 'https://github.com/neonlabsorg/proxy-model.py/issues/365'

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


def send_routine(acc_seed, storage_contract, loop, return_dict, padding_string):
    print("Send parallel transaction from {}".format(acc_seed))
    print(datetime.datetime.now().time())
    proxy = Proxy()
    new_eth_account = proxy.create_signer_account(acc_seed)
    tx_store = storage_contract.functions.add_some(2, loop, padding_string).build_transaction({
        'from': new_eth_account.address
    })
    tx_store = proxy.sign_send_wait_transaction(new_eth_account, tx_store)
    return_dict[acc_seed] = tx_store.tx_receipt


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
        cls.proxy = Proxy()
        cls.eth_account = cls.proxy.create_signer_account(SEED)

        print("\ntest_retry_on_blocked_accounts.py setUpClass")

        wallet = WalletAccount(wallet_path())
        cls.loader = loader = EvmLoader(wallet, EVM_LOADER)

        cls.config = config = Config()
        cls.solana = solana = SolInteractor(config, config.solana_url)

        cls.resource_iter = resource = OpResInfo(wallet.get_acc(), 365)
        OpResInit(FakeConfig(), solana).init_resource(resource)

        cls.resource_single = resource = OpResInfo(wallet.get_acc(), 366)
        OpResInit(FakeConfig(), solana).init_resource(resource)

        deployed_info = cls.proxy.compile_and_deploy_contract(cls.eth_account, TEST_RETRY_BLOCKED_365)
        cls.storage_contract = deployed_info.contract

        print(deployed_info.contract.address)

        reid_eth = deployed_info.contract.address.lower()
        print('contract_eth', reid_eth)
        cls.re_id, _ = re_id, _ = loader.ether2program(reid_eth)
        print('contract', re_id)

        cls.caller, _ = loader.ether2program(cls.eth_account.address)

    def create_blocked_transaction(self, resource):
        print("\ncreate_blocked_transaction")
        tx_store = self.storage_contract.functions.add_some(1, 30, "").build_transaction({
            'from': self.eth_account.address
        })
        tx_store = self.proxy.sign_transaction(self.eth_account, tx_store)
        print(f'blocked tx hash: {tx_store.tx_signed.hash.hex()}')

        neon_ix_builder = NeonIxBuilder(resource.public_key)
        neon_ix_builder.init_operator_neon(NeonAddress.from_private_key(resource.secret_key))

        neon_tx = NeonTx.from_string(tx_store.tx_signed.rawTransaction)
        neon_ix_builder.init_neon_tx(neon_tx)
        neon_ix_builder.init_neon_account_list([
            SolAccountMeta(pubkey=self.re_id, is_signer=False, is_writable=True),
            SolAccountMeta(pubkey=self.caller, is_signer=False, is_writable=True)
        ])

        neon_ix_builder.init_iterative(resource.holder)

        solana_tx = SolLegacyTx(instructions=[
            neon_ix_builder.make_compute_budget_heap_ix(),
            neon_ix_builder.make_compute_budget_cu_ix(),
            neon_ix_builder.make_tx_step_from_data_ix(500, 1)
        ])

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
                caller_seed, self.storage_contract, 50, return_dict,
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
            args=(caller_seed, self.storage_contract, 10, return_dict, ""))
        p2.start()
        self.finish_blocker_transaction(solana_tx, self.resource_single)
        p2.join()
        print('test_blocked_single return_dict:', return_dict)
        self.assertEqual(return_dict[caller_seed]['status'], 1)


if __name__ == '__main__':
    unittest.main()
