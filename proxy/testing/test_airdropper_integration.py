from unittest import TestCase
from solana.rpc.api import Client as SolanaClient
from solana.account import Account as SolanaAccount
from spl.token.client import Token as SplToken
from ..common_neon.environment_data import SOLANA_URL, EVM_LOADER_ID
from ..common_neon.web3 import NeonWeb3
from solana.system_program import SYS_PROGRAM_ID
from spl.token.constants import TOKEN_PROGRAM_ID
from solana.rpc.commitment import Confirmed
from solana.publickey import PublicKey
from solana.rpc.types import TxOpts
from solana.transaction import TransactionInstruction, AccountMeta, Transaction
from proxy.common_neon.neon_instruction import create_account_layout
from proxy.common_neon.erc20_wrapper import ERC20Wrapper
from time import sleep
from web3 import Web3
import os
import json
import unittest
import spl.token.instructions as SplTokenInstrutions

from proxy.testing.testing_helpers import request_airdrop

MAX_AIRDROP_WAIT_TIME = 45
EVM_LOADER_ID = PublicKey(EVM_LOADER_ID)
PROXY_URL = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
FAUCET_RPC_PORT = 3333
NAME = 'TestToken'
SYMBOL = 'TST'
proxy = NeonWeb3(Web3.HTTPProvider(PROXY_URL))
admin = proxy.eth.account.create('neonlabsorg/proxy-model.py/issues/344/admin20')
proxy.eth.default_account = admin.address
request_airdrop(admin.address)


# Helper function calculating solana address and nonce from given NEON(Ethereum) address
def get_evm_loader_account_address(eth_address: str):
    eth_addressbytes = bytes.fromhex(eth_address[2:])
    return PublicKey.find_program_address([b"\1", eth_addressbytes], EVM_LOADER_ID)


class TestAirdropperIntegration(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.create_token_mint(cls)
        cls.deploy_erc20_wrapper_contract(cls)
        cls.acc_num = 0

    def create_token_mint(self):
        self.solana_client = SolanaClient(SOLANA_URL)

        with open("proxy/operator-keypairs/id.json") as f:
            d = json.load(f)
        self.mint_authority = SolanaAccount(d[0:32])
        self.solana_client.request_airdrop(self.mint_authority.public_key(), 1000_000_000_000, Confirmed)

        while True:
            balance = self.solana_client.get_balance(self.mint_authority.public_key(), Confirmed)["result"]["value"]
            if balance > 0:
                break
            sleep(1)
        print('create_token_mint mint, SolanaAccount: ', self.mint_authority.public_key())

        self.token = SplToken.create_mint(
            self.solana_client,
            self.mint_authority,
            self.mint_authority.public_key(),
            9,
            TOKEN_PROGRAM_ID,
        )

    def deploy_erc20_wrapper_contract(self):
        self.wrapper = ERC20Wrapper(proxy, NAME, SYMBOL,
                                    self.token, admin,
                                    self.mint_authority,
                                    EVM_LOADER_ID)
        self.wrapper.deploy_wrapper()

    @staticmethod
    def create_account_instruction(eth_address: str, payer: PublicKey):
        dest_address_solana, nonce = get_evm_loader_account_address(eth_address)
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=create_account_layout(bytes.fromhex(eth_address[2:]), nonce),
            keys=[
                AccountMeta(pubkey=payer, is_signer=True, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=dest_address_solana, is_signer=False, is_writable=True),
            ])

    def create_sol_account(self):
        account = SolanaAccount()
        print(f"New solana account created: {account.public_key().to_base58()}. Airdropping...")
        self.solana_client.request_airdrop(account.public_key(), 1000_000_000_000, Confirmed)
        return account

    def create_token_account(self, owner: PublicKey, mint_amount: int):
        new_token_account = self.wrapper.create_associated_token_account(owner, self.mint_authority)
        self.wrapper.mint_to(new_token_account, mint_amount)
        return new_token_account

    def create_eth_account(self):
        self.acc_num += 1
        account = proxy.eth.account.create(f'neonlabsorg/proxy-model.py/issues/344/eth_account{self.acc_num}')
        print(f"NEON account created: {account.address}")
        return account

    def test_success_airdrop_simple_case(self):
        from_owner = self.create_sol_account()
        mint_amount = 1000_000_000_000
        from_spl_token_acc = self.create_token_account(from_owner.public_key(), mint_amount)
        to_neon_acc = self.create_eth_account()

        print(f'        OWNER {from_owner.public_key()}')
        print(f'            SPL TOKEN ACC {from_spl_token_acc}')

        self.assertEqual(self.wrapper.get_balance(from_spl_token_acc), mint_amount)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc.address), 0)

        TRANSFER_AMOUNT = 123456
        trx = Transaction()
        trx.add(self.create_account_instruction(to_neon_acc.address, from_owner.public_key()))
        trx.add(SplTokenInstrutions.approve(SplTokenInstrutions.ApproveParams(
            program_id=self.token.program_id,
            source=from_spl_token_acc,
            delegate=self.wrapper.get_neon_account_address(to_neon_acc.address),
            owner=from_owner.public_key(),
            amount=TRANSFER_AMOUNT,
            signers=[],
        )))
        claim_instr = self.wrapper.create_claim_instruction(
            owner=from_owner.public_key(),
            from_acc=from_spl_token_acc,
            to_acc=to_neon_acc,
            amount=TRANSFER_AMOUNT,
        )
        trx.add(claim_instr.make_tx_exec_from_data_ix())

        opts = TxOpts(skip_preflight=True, skip_confirmation=False)
        print(self.solana_client.send_transaction(trx, from_owner, opts=opts))

        self.assertEqual(self.wrapper.get_balance(from_spl_token_acc), mint_amount - TRANSFER_AMOUNT)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc.address), TRANSFER_AMOUNT)

        eth_balance = proxy.eth.get_balance(to_neon_acc.address)
        print("NEON balance before is: ", eth_balance)

        wait_time = 0
        while wait_time < MAX_AIRDROP_WAIT_TIME:
            eth_balance = proxy.eth.get_balance(to_neon_acc.address)
            balance_ready = eth_balance > 0 and eth_balance < 10 * pow(10, 18)
            if balance_ready:
                break
            sleep(1)
            wait_time += 1
        print(f"Wait time for simple transaction (1 airdrop): {wait_time}")

        eth_balance = proxy.eth.get_balance(to_neon_acc.address)
        print("NEON balance is: ", eth_balance)
        self.assertTrue(eth_balance > 0 and eth_balance < 10 * pow(10, 18))  # 10 NEON is a max airdrop amount

    @unittest.skip('Test case is not applicable after introducing ERC20-for-SPL. Postponed for a better times')
    def test_success_airdrop_complex_case(self):
        from_owner = self.create_sol_account()
        mint_amount = 1000_000_000_000
        from_spl_token_acc = self.create_token_account(from_owner.public_key(), mint_amount)
        to_neon_acc1 = self.create_eth_account()
        to_neon_acc2 = self.create_eth_account()

        self.assertEqual(self.wrapper.get_balance(from_spl_token_acc), mint_amount)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc1.address), 0)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc2.address), 0)

        TRANSFER_AMOUNT1 = 123456
        TRANSFER_AMOUNT2 = 654321
        tx = Transaction()
        tx.add(self.create_account_instruction(to_neon_acc1.address, from_owner.public_key()))
        tx.add(self.create_account_instruction(to_neon_acc2.address, from_owner.public_key()))
        tx.add(SplTokenInstrutions.approve(SplTokenInstrutions.ApproveParams(
            program_id=self.token.program_id,
            source=from_spl_token_acc,
            delegate=self.wrapper.get_neon_account_address(to_neon_acc1.address),
            owner=from_owner.public_key(),
            amount=TRANSFER_AMOUNT1,
            signers=[],
        )))
        tx.add(SplTokenInstrutions.approve(SplTokenInstrutions.ApproveParams(
            program_id=self.token.program_id,
            source=from_spl_token_acc,
            delegate=self.wrapper.get_neon_account_address(to_neon_acc2.address),
            owner=from_owner.public_key(),
            amount=TRANSFER_AMOUNT2,
            signers=[],
        )))
        claim_instr1 = self.wrapper.create_claim_instruction(
            owner=from_owner.public_key(),
            from_acc=from_spl_token_acc,
            to_acc=to_neon_acc1,
            amount=TRANSFER_AMOUNT1,
        )
        tx.add(claim_instr1.make_tx_exec_from_data_ix())
        claim_instr2 = self.wrapper.create_claim_instruction(
            owner=from_owner.public_key(),
            from_acc=from_spl_token_acc,
            to_acc=to_neon_acc2,
            amount=TRANSFER_AMOUNT2,
        )
        tx.add(claim_instr2.make_tx_exec_from_data_ix())

        opts = TxOpts(skip_preflight=True, skip_confirmation=False)
        print(self.solana_client.send_transaction(trx, from_owner, opts=opts))

        self.assertEqual(self.wrapper.get_balance(from_spl_token_acc), mint_amount - TRANSFER_AMOUNT1 - TRANSFER_AMOUNT2)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc1.address), TRANSFER_AMOUNT1)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc2.address), TRANSFER_AMOUNT2)

        wait_time = 0
        while wait_time < MAX_AIRDROP_WAIT_TIME:
            eth_balance1 = proxy.eth.get_balance(to_neon_acc1.address)
            eth_balance2 = proxy.eth.get_balance(to_neon_acc2.address)
            balance1_ready = eth_balance1 > 0 and eth_balance1 < 10 * pow(10, 18)
            balance2_ready = eth_balance2 > 0 and eth_balance2 < 10 * pow(10, 18)
            if balance1_ready and balance2_ready:
                break
            sleep(1)
            wait_time += 1
        print(f"Wait time for complex transaction (2 airdrops): {wait_time}")

        eth_balance1 = proxy.eth.get_balance(to_neon_acc1.address)
        eth_balance2 = proxy.eth.get_balance(to_neon_acc2.address)
        print("NEON balance 1 is: ", eth_balance1)
        print("NEON balance 2 is: ", eth_balance2)
        self.assertTrue(eth_balance1 > 0 and eth_balance1 < 10 * pow(10, 18))  # 10 NEON is a max airdrop amount
        self.assertTrue(eth_balance2 > 0 and eth_balance2 < 10 * pow(10, 18))  # 10 NEON is a max airdrop amount

    def test_no_airdrop(self):
        from_owner = self.create_sol_account()
        mint_amount = 1000_000_000_000
        from_spl_token_acc = self.create_token_account(from_owner.public_key(), mint_amount)
        to_neon_acc = self.create_eth_account()

        initial_balance = 1_000
        # Create account before input liquidity (should not cause airdrop)
        request_airdrop(to_neon_acc.address, initial_balance)
        sleep(15)

        self.assertEqual(self.wrapper.get_balance(from_spl_token_acc), mint_amount)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc.address), 0)  # Destination-acc ERC20-Token balance is 0
        self.assertEqual(proxy.eth.get_balance(to_neon_acc.address), initial_balance * 10**18)  # Destination-acc Neon balance is initial

        TRANSFER_AMOUNT = 123456
        trx = Transaction()
        trx.add(SplTokenInstrutions.approve(SplTokenInstrutions.ApproveParams(
            program_id=self.token.program_id,
            source=from_spl_token_acc,
            delegate=self.wrapper.get_neon_account_address(to_neon_acc.address),
            owner=from_owner.public_key(),
            amount=TRANSFER_AMOUNT,
            signers=[],
        )))
        claim_instr = self.wrapper.create_claim_instruction(
            owner=from_owner.public_key(),
            from_acc=from_spl_token_acc,
            to_acc=to_neon_acc,
            amount=TRANSFER_AMOUNT,
        )
        trx.add(claim_instr.make_tx_exec_from_data_ix())

        opts = TxOpts(skip_preflight=True, skip_confirmation=False)
        print(self.solana_client.send_transaction(trx, from_owner, opts=opts))

        sleep(15)
        self.assertEqual(self.wrapper.get_balance(from_spl_token_acc), mint_amount - TRANSFER_AMOUNT)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc.address), TRANSFER_AMOUNT)
        eth_balance = proxy.eth.get_balance(to_neon_acc.address)
        print("NEON balance is: ", eth_balance)
        # Balance should not change because airdropper should not handle this transaction
        self.assertEqual(eth_balance, initial_balance * 10**18)
