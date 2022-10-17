## File: test_erc20_wrapper_contract.py
## Integration test for the Neon ERC20 Wrapper contract.

import unittest
import json

from time import sleep

from solana.rpc.api import Client as SolanaClient

from spl.token.client import Token as SplToken
from spl.token.constants import TOKEN_PROGRAM_ID

from proxy.common_neon.config import Config
from proxy.common_neon.solana_tx import SolAccount, SolPubKey
from proxy.common_neon.erc20_wrapper import ERC20Wrapper

from proxy.testing.testing_helpers import Proxy


CONTRACT = '''
pragma solidity >= 0.7.0;

contract ReadOnly {

    function balanceOf(address a) public view returns(uint256) {
        return a.balance;
    }
}
'''


class TestReadOnlyAccounts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = Config()
        cls.proxy = Proxy()
        cls.admin = cls.proxy.create_signer_account('issues/neonlabsorg/proxy-model.py/197/readonly')
        cls.create_token_mint(cls)
        cls.deploy_erc20_wrapper_contract(cls)
        cls.deploy_test_contract(cls)

    def account_exists(self, key: SolPubKey) -> bool:
        info = self.solana_client.get_account_info(key)
        return info.value is not None

    def create_token_mint(self):
        self.solana_client = SolanaClient(self.config.solana_url)

        with open("proxy/operator-keypairs/id.json") as f:
            d = json.load(f)
        self.solana_account = SolAccount.from_secret_key(bytes(d))
        print('Account: ', self.solana_account.public_key)
        self.solana_client.request_airdrop(self.solana_account.public_key, 1000_000_000_000)

        for i in range(20):
            sleep(1)
            balance = self.solana_client.get_balance(self.solana_account.public_key).value
            if balance == 0:
                continue

            try:
                self.token = SplToken.create_mint(
                    self.solana_client,
                    self.solana_account,
                    self.solana_account.public_key,
                    9,
                    TOKEN_PROGRAM_ID,
                )
                print(
                    'create_token_mint mint, SolanaAccount: ',
                    self.solana_client.get_account_info(self.solana_account.public_key)
                )
                return
            except (Exception,):
                continue
        self.assertTrue(False)

    def deploy_erc20_wrapper_contract(self):
        self.wrapper = ERC20Wrapper(
            self.proxy.web3, "NEON", "NEON",
            self.token, self.admin,
            self.solana_account,
            self.config.evm_loader_id
        )
        self.wrapper.deploy_wrapper()

    def deploy_test_contract(self):
        deployed_info = self.proxy.compile_and_deploy_contract(self.admin, CONTRACT)
        self.contract = deployed_info.contract

    def test_balanceOf(self):
        account = self.proxy.create_account()

        solana_account = self.wrapper.get_neon_account_address(account.address)
        self.assertFalse(self.account_exists(solana_account))

        tx = self.contract.functions.balanceOf(account.address).build_transaction({"from": self.admin.address})
        tx = self.proxy.sign_send_wait_transaction(self.admin, tx)

        self.assertEqual(tx.tx_receipt.status, 1)

        self.assertFalse(self.account_exists(solana_account))

    def test_erc20_balanceOf(self):
        erc20 = self.wrapper.erc20_interface()

        account = self.proxy.create_account()

        solana_account = self.wrapper.get_neon_account_address(account.address)
        self.assertFalse(self.account_exists(solana_account))

        token_account = self.wrapper.get_neon_erc20_account_address(account.address)
        self.assertFalse(self.account_exists(token_account))

        tx = erc20.functions.balanceOf(account.address).build_transaction({"from": self.admin.address})
        tx = self.proxy.sign_send_wait_transaction(self.admin, tx)

        self.assertEqual(tx.tx_receipt.status, 1)

        self.assertFalse(self.account_exists(solana_account))
        self.assertFalse(self.account_exists(token_account))


if __name__ == '__main__':
    unittest.main()
