import unittest

import solders.rpc.errors
from solana.rpc.api import Client as SolanaClient
from solana.rpc.types import TxOpts
from solana.rpc.commitment import Confirmed

from spl.token.client import Token as SplToken
from spl.token.instructions import get_associated_token_address, create_associated_token_account
from spl.token.constants import TOKEN_PROGRAM_ID

from random import uniform
from eth_account.signers.local import LocalAccount as NeonAccount

from proxy.common_neon.config import Config
from proxy.common_neon.solana_tx import SolAccount
from proxy.common_neon.solana_tx_legacy import SolLegacyTx
from proxy.common_neon.elf_params import ElfParams

from proxy.testing.testing_helpers import Proxy


class TestNeonToken(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.proxy = Proxy()
        cls.solana = SolanaClient(Config().solana_url)
        cls.sol_payer = SolAccount()
        cls.deploy_contract(cls)
        cls.spl_neon_token = SplToken(cls.solana, ElfParams().neon_token_mint, TOKEN_PROGRAM_ID, cls.sol_payer)

    def create_eth_account(self, balance: int):
        seed = f'TestAccount{uniform(0, 10000)}'
        new_neon_acc = self.proxy.create_signer_account(seed, balance)
        print(f"New Neon account {new_neon_acc.address} with balance {balance}")
        return new_neon_acc

    def create_sol_account(self, balance: int = 1000_000_000_000):
        new_sol_acc = SolAccount()
        print(f"New Solana account {new_sol_acc.pubkey()} with balance {balance}")
        self.solana.request_airdrop(new_sol_acc.pubkey(), balance)
        return new_sol_acc

    def deploy_contract(self):
        deployer = self.proxy.create_signer_account()
        deployed_info = self.proxy.compile_and_deploy_from_file(deployer, '/opt/contracts/neon_wrapper.sol')
        self.neon_token_address = deployed_info.contract.address
        print(f'NeonToken contract address is: {self.neon_token_address}')
        self.neon_contract = deployed_info.contract

    def withdraw(self, source_acc: NeonAccount, dest_acc: SolAccount, withdraw_amount_alan: int):
        tx = {'value': withdraw_amount_alan, 'from': source_acc.address}
        withdraw_tx = self.neon_contract.functions.withdraw(bytes(dest_acc.pubkey())).build_transaction(tx)
        withdraw_tx = self.proxy.sign_send_wait_transaction(source_acc, withdraw_tx)
        print(f'withdraw_tx_hash: {withdraw_tx.tx_hash.hex()}')
        print(f'withdraw_tx_receipt: {withdraw_tx.tx_receipt}')

    def test_success_withdraw_to_non_existing_account(self):
        """
        Should successfully withdraw NEON tokens to previously non-existing Associated Token Account
        """
        print()
        print('test_success_withdraw_to_non_existing_account')

        source_acc = self.create_eth_account(10)
        dest_acc = self.create_sol_account()

        dest_token_acc = get_associated_token_address(dest_acc.pubkey(), ElfParams().neon_token_mint)
        print(f"Destination token account: {dest_token_acc}")

        withdraw_amount_alan = pow(10, 18) # 1 NEON
        withdraw_amount_galan = int(withdraw_amount_alan / 1_000_000_000)

        # Check source balance
        source_balance_before_alan = self.proxy.conn.get_balance(source_acc.address)
        print(f'Source account balance before (Alan): {source_balance_before_alan}')

        # Check destination balance (must not exist)
        destination_balance_before_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance before (Galan): {destination_balance_before_galan}')
        self.assertTrue(isinstance(destination_balance_before_galan, solders.rpc.errors.InvalidParamsMessage))

        self.withdraw(source_acc, dest_acc, withdraw_amount_alan)

        # Check source balance
        source_balance_after_alan = self.proxy.conn.get_balance(source_acc.address)
        print(f'Source account balance after (Alan): {source_balance_after_alan}')
        self.assertLess(source_balance_after_alan, source_balance_before_alan - withdraw_amount_alan)

        # Check destination balance
        destination_balance_after_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance after (Galan): {destination_balance_after_galan}')
        self.assertEqual(int(destination_balance_after_galan.value.amount), withdraw_amount_galan)

    def test_success_withdraw_to_existing_account(self):
        """
        Should succesfully withdraw NEON tokens to existing Associated Token Account
        """
        print()
        print('test_success_withdraw_to_existing_account')

        source_acc = self.create_eth_account(100)
        dest_acc = self.create_sol_account()

        # Creating destination Associated Token Account
        tx = SolLegacyTx(instructions=[
            create_associated_token_account(
                dest_acc.pubkey(),
                dest_acc.pubkey(),
                ElfParams().neon_token_mint
            )
        ])
        opts = TxOpts(skip_preflight=True, skip_confirmation=False)
        resp = self.solana.send_transaction(tx.low_level_tx, dest_acc, opts=opts)
        print(f'Create account: {resp}')

        dest_token_acc = get_associated_token_address(dest_acc.pubkey(), ElfParams().neon_token_mint)
        print(f"Destination token account: {dest_token_acc}")

        withdraw_amount_alan = 2_123_000_321_000_000_000
        withdraw_amount_galan = int(withdraw_amount_alan / 1_000_000_000)

        # Check source balance
        source_balance_before_alan = self.proxy.conn.get_balance(source_acc.address)
        print(f'Source account {source_acc.address} balance before (Alan): {source_balance_before_alan}')

        # Check destination balance (must exist with zero balance)
        resp = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        destination_balance_before_galan = int(resp.value.amount)
        print(f'Destination account balance before (Galan): {destination_balance_before_galan}')
        self.assertEqual(destination_balance_before_galan, 0)

        self.withdraw(source_acc, dest_acc, withdraw_amount_alan)

        # Check source balance
        source_balance_after_alan = self.proxy.conn.get_balance(source_acc.address)
        print(f'Source account balance after (Alan): {source_balance_after_alan}')
        self.assertLess(source_balance_after_alan, source_balance_before_alan - withdraw_amount_alan)

        # Check destination balance
        resp = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        destination_balance_after_galan = int(resp.value.amount)
        print(f'Destination account balance after (Galan): {destination_balance_after_galan}')
        self.assertEqual(destination_balance_after_galan, withdraw_amount_galan)

    def test_failed_withdraw_non_divisible_amount(self):
        """
        Should fail withdrawal because amount not divised by 1 billion
        """
        print()
        print('test_failed_withdraw_non_divisible_amount')

        source_acc = self.create_eth_account(10)
        dest_acc = self.create_sol_account()

        dest_token_acc = get_associated_token_address(dest_acc.pubkey(), ElfParams().neon_token_mint)
        print(f"Destination token account: {dest_token_acc}")

        withdraw_amount_alan = pow(10, 18) + 123 # NEONs

        # Check source balance
        source_balance_before_alan = self.proxy.conn.get_balance(source_acc.address)
        print(f'Source account balance before (Alan): {source_balance_before_alan}')

        # Check destination balance (must not exist)
        destination_balance_before_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance before (Galan): {destination_balance_before_galan}')
        self.assertTrue(isinstance(destination_balance_before_galan, solders.rpc.errors.InvalidParamsMessage))

        with self.assertRaises(ValueError) as er:
            self.withdraw(source_acc, dest_acc, withdraw_amount_alan)
        print(f'Exception occured: {er.exception}')

        # Check source balance
        source_balance_after_alan = self.proxy.conn.get_balance(source_acc.address)
        print(f'Source account balance after (Alan): {source_balance_after_alan}')
        self.assertEqual(source_balance_after_alan, source_balance_before_alan)

        # Check destination balance
        destination_balance_after_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance after (Galan): {destination_balance_after_galan}')
        self.assertTrue(isinstance(destination_balance_before_galan, solders.rpc.errors.InvalidParamsMessage))

    def test_failed_withdraw_insufficient_balance(self):
        """
        Should fail withdrawal because of insufficient balance
        """
        print()
        print('test_failed_withdraw_insufficient_balance')

        source_acc = self.create_eth_account(1)
        dest_acc = self.create_sol_account()

        dest_token_acc = get_associated_token_address(dest_acc.pubkey(), ElfParams().neon_token_mint)
        print(f"Destination token account: {dest_token_acc}")

        withdraw_amount_alan = 2 * pow(10, 18) # 2 NEONs

        # Check source balance
        source_balance_before_alan = self.proxy.conn.get_balance(source_acc.address)
        print(f'Source account balance before (Alan): {source_balance_before_alan}')

        # Check destination balance (must not exist)
        destination_balance_before_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance before (Galan): {destination_balance_before_galan}')
        self.assertTrue(isinstance(destination_balance_before_galan, solders.rpc.errors.InvalidParamsMessage))

        with self.assertRaises(ValueError) as er:
            self.withdraw(source_acc, dest_acc, withdraw_amount_alan)
        print(f'Exception occured: {er.exception}')

        # Check source balance
        source_balance_after_alan = self.proxy.conn.get_balance(source_acc.address)
        print(f'Source account balance after (Alan): {source_balance_after_alan}')
        self.assertEqual(source_balance_after_alan, source_balance_before_alan)

        # Check destination balance
        destination_balance_after_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance after (Galan): {destination_balance_after_galan}')
        self.assertTrue(isinstance(destination_balance_after_galan, solders.rpc.errors.InvalidParamsMessage))

    def test_failed_withdraw_all_balance(self):
        """
        Should fail withdrawal all balance
        """

        print()
        print('test_failed_withdraw_all_balance')

        source_acc = self.create_eth_account(1) # 1 NEON
        dest_acc = self.create_sol_account()

        dest_token_acc = get_associated_token_address(dest_acc.pubkey(), ElfParams().neon_token_mint)
        print(f"Destination token account: {dest_token_acc}")

        withdraw_amount_alan = 1_000_000_000_000_000_000 # 1 NEON

        # Check source balance
        source_balance_before_alan = self.proxy.conn.get_balance(source_acc.address)
        print(f'Source account balance before (Alan): {source_balance_before_alan}')

        # Check destination balance (must not exist)
        destination_balance_before_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance before (Galan): {destination_balance_before_galan}')
        self.assertTrue(isinstance(destination_balance_before_galan, solders.rpc.errors.InvalidParamsMessage))

        with self.assertRaises(ValueError) as er:
            self.withdraw(source_acc, dest_acc, withdraw_amount_alan)
        print(f'Exception occured: {er.exception}')

        # Check source balance
        source_balance_after_alan = self.proxy.conn.get_balance(source_acc.address)
        print(f'Source account balance after (Alan): {source_balance_after_alan}')
        self.assertEqual(source_balance_after_alan, source_balance_before_alan)

        # Check destination balance
        destination_balance_after_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance after (Galan): {destination_balance_after_galan}')
        self.assertTrue(isinstance(destination_balance_after_galan, solders.rpc.errors.InvalidParamsMessage))
