## File: test_erc20_wrapper_contract.py
## Integration test for the Neon ERC20 Wrapper contract.

import unittest
import json

from time import sleep

from solana.rpc.commitment import Confirmed, Processed
from solana.rpc.types import TxOpts, TokenAccountOpts
from solana.rpc.api import Client as SolanaClient
from solana.transaction import Transaction
from solana.publickey import PublicKey

from spl.token.client import Token as SplToken
from spl.token.constants import TOKEN_PROGRAM_ID
import spl.token.instructions as SplTokenInstrutions

from ..common_neon.metaplex import create_metadata_instruction_data,create_metadata_instruction

from proxy.testing.testing_helpers import Proxy
from proxy.common_neon.constants import COMPUTE_BUDGET_ID
from proxy.common_neon.solana_tx import SolAccount, SolTxIx
from proxy.common_neon.solana_tx_legacy import SolLegacyTx
from proxy.common_neon.erc20_wrapper import ERC20Wrapper
from proxy.common_neon.config import Config
from proxy.common_neon.elf_params import ElfParams

NAME = 'NEON'
SYMBOL = 'NEO'
DECIMALS = 9


class Test_erc20ForSpl_contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proxy = Proxy()
        cls.admin = cls.proxy.create_signer_account('issues/neonlabsorg/proxy-model.py/197/admin')
        cls.user = cls.proxy.create_signer_account('issues/neonlabsorg/proxy-model.py/197/user')
        cls.config = Config()
        cls.elf_params = ElfParams()

        print("\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/197")
        print('admin.key:', cls.admin.key.hex())
        print('admin.address:', cls.admin.address)
        print('user.key:', cls.user.key.hex())
        print('user.address:', cls.user.address)

        cls.init_solana_client(cls)
        cls.create_token_mint(cls)
        cls.deploy_erc20_wrapper_contract(cls)
        cls.create_token_accounts(cls)

    def init_solana_client(self):
        self.solana_client = SolanaClient(self.config.solana_url)

        with open("proxy/operator-keypairs/id3.json") as f:
            d = json.load(f)
        self.solana_account = solana_account = SolAccount.from_secret_key(bytes(d))
        print('Account: ', solana_account.public_key)
        self.solana_client.request_airdrop(solana_account.public_key, 1000_000_000_000)

    def create_token_mint(self):
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

                print(f'Created new token mint: {self.token.pubkey}')

                metadata = create_metadata_instruction_data(NAME, SYMBOL, 0, ())
                txn = Transaction()
                txn.add(
                    create_metadata_instruction(
                        metadata,
                        self.solana_account.public_key,
                        self.token.pubkey,
                        self.solana_account.public_key,
                        self.solana_account.public_key,
                    )
                )
                self.solana_client.send_transaction(txn, self.solana_account, opts=TxOpts(preflight_commitment=Confirmed, skip_confirmation=False))

                return
            except Exception as err:
                print(f"Error: {err}")
                continue
        self.assertTrue(False)

    def deploy_erc20_wrapper_contract(self):
        self.wrapper = ERC20Wrapper(
            self.proxy.web3, NAME, SYMBOL,
            self.token, self.admin,
            self.solana_account,
            self.config.evm_loader_id
        )
        self.wrapper.deploy_wrapper()

    def create_token_accounts(self):
        amount = 10_000_000_000_000
        token_account = SplTokenInstrutions.get_associated_token_address(
            self.solana_account.public_key, self.token.pubkey)
        admin_address = self.wrapper.get_neon_account_address(self.admin.address)

        tx = SolLegacyTx(instructions=[
            SolTxIx(
                program_id=COMPUTE_BUDGET_ID,
                keys=[],
                data=bytes.fromhex("01") + self.elf_params.neon_heap_frame.to_bytes(4, "little")
            ),
            SolTxIx(
                program_id=COMPUTE_BUDGET_ID,
                keys=[],
                data=bytes.fromhex("02") + self.elf_params.neon_compute_units.to_bytes(4, "little")
            ),
            SplTokenInstrutions.create_associated_token_account(
                self.solana_account.public_key, self.solana_account.public_key, self.token.pubkey
            )
        ])
        tx.add(SplTokenInstrutions.mint_to(SplTokenInstrutions.MintToParams(
            program_id=self.token.program_id,
            mint=self.token.pubkey,
            dest=token_account,
            mint_authority=self.solana_account.public_key,
            amount=amount,
            signers=[],
        )))
        tx.add(SplTokenInstrutions.approve(SplTokenInstrutions.ApproveParams(
            program_id=self.token.program_id,
            source=token_account,
            delegate=admin_address,
            owner=self.solana_account.public_key,
            amount=amount,
            signers=[],
        )))

        claim_instr = self.wrapper.create_claim_instruction(
            owner=self.solana_account.public_key,
            from_acc=token_account,
            to_acc=self.admin,
            amount=amount,
        )
        tx.add(claim_instr.make_tx_exec_from_data_ix())

        self.solana_client.send_transaction(
            tx.low_level_tx, self.solana_account, opts=TxOpts(preflight_commitment=Confirmed, skip_confirmation=False))

    def test_erc20_name(self):
        erc20 = self.proxy.conn.contract(address=self.wrapper.neon_contract_address, abi=self.wrapper.wrapper['abi'])
        name = erc20.functions.name().call()
        self.assertEqual(name, NAME)

    def test_erc20_symbol(self):
        erc20 = self.proxy.conn.contract(address=self.wrapper.neon_contract_address, abi=self.wrapper.wrapper['abi'])
        sym = erc20.functions.symbol().call()
        self.assertEqual(sym, SYMBOL)

    def test_erc20_decimals(self):
        erc20 = self.wrapper.erc20_interface()
        decs = erc20.functions.decimals().call()
        self.assertEqual(decs, 9)

    def test_erc20_totalSupply(self):
        erc20 = self.wrapper.erc20_interface()
        ts = erc20.functions.totalSupply().call()
        self.assertGreater(ts, 0)

    def test_erc20_balanceOf(self):
        erc20 = self.wrapper.erc20_interface()
        b = erc20.functions.balanceOf(self.admin.address).call()
        self.assertGreater(b, 0)
        b = erc20.functions.balanceOf(self.user.address).call()
        self.assertEqual(b, 0)

    def test_erc20_transfer(self):
        transfer_value = 1000
        erc20 = self.wrapper.erc20_interface()

        admin_balance_before = erc20.functions.balanceOf(self.admin.address).call()
        user_balance_before = erc20.functions.balanceOf(self.user.address).call()

        tx = {'from': self.admin.address}
        tx = erc20.functions.transfer(self.user.address, transfer_value).build_transaction(tx)
        tx = self.proxy.sign_send_wait_transaction(self.admin, tx)
        self.assertEqual(tx.tx_receipt.status, 1)

        admin_balance_after = erc20.functions.balanceOf(self.admin.address).call()
        user_balance_after = erc20.functions.balanceOf(self.user.address).call()

        self.assertEqual(admin_balance_after, admin_balance_before - transfer_value)
        self.assertEqual(user_balance_after, user_balance_before + transfer_value)

    def test_erc20_transfer_not_enough_funds(self):
        transfer_value = 100_000_000_000_000
        erc20 = self.wrapper.erc20_interface()

        admin_balance_before = erc20.functions.balanceOf(self.admin.address).call()
        user_balance_before = erc20.functions.balanceOf(self.user.address).call()

        with self.assertRaisesRegex(Exception, "execution reverted: ERC20: transfer from the zero address"):
            erc20.functions.transfer(self.user.address, transfer_value).build_transaction()

        admin_balance_after = erc20.functions.balanceOf(self.admin.address).call()
        user_balance_after = erc20.functions.balanceOf(self.user.address).call()

        self.assertEqual(admin_balance_after, admin_balance_before)
        self.assertEqual(user_balance_after, user_balance_before)

    def test_erc20_transfer_out_of_bounds(self):
        transfer_value = 0xFFFF_FFFF_FFFF_FFFF + 1
        erc20 = self.wrapper.erc20_interface()

        with self.assertRaisesRegex(Exception, "ERC20: transfer amount exceeds uint64 max"):
            erc20.functions.transfer(self.user.address, transfer_value).build_transaction({"from": self.admin.address})

    def test_erc20_approve(self):
        approve_value = 1000
        erc20 = self.wrapper.erc20_interface()

        allowance_before = erc20.functions.allowance(self.admin.address, self.user.address).call()

        tx = erc20.functions.approve(self.user.address, approve_value).build_transaction({"from": self.admin.address})
        tx = self.proxy.sign_send_wait_transaction(self.admin, tx)
        self.assertEqual(tx.tx_receipt.status, 1)

        allowance_after = erc20.functions.allowance(self.admin.address, self.user.address).call()
        self.assertEqual(allowance_after, allowance_before + approve_value)

    def test_erc20_transferFrom(self):
        approve_value = 1000
        transfer_value = 100
        erc20 = self.wrapper.erc20_interface()

        tx = erc20.functions.approve(self.user.address, approve_value).build_transaction({'from': self.admin.address})
        tx = self.proxy.sign_send_wait_transaction(self.admin, tx)
        self.assertEqual(tx.tx_receipt.status, 1)

        allowance_before = erc20.functions.allowance(self.admin.address, self.user.address).call()
        admin_balance_before = erc20.functions.balanceOf(self.admin.address).call()
        user_balance_before = erc20.functions.balanceOf(self.user.address).call()

        tx = erc20.functions.transferFrom(self.admin.address, self.user.address, transfer_value).build_transaction(
            {'from': self.user.address}
        )
        tx = self.proxy.sign_send_wait_transaction(self.user, tx)
        self.assertEqual(tx.tx_receipt.status, 1)

        allowance_after = erc20.functions.allowance(self.admin.address, self.user.address).call()
        admin_balance_after = erc20.functions.balanceOf(self.admin.address).call()
        user_balance_after = erc20.functions.balanceOf(self.user.address).call()

        self.assertEqual(allowance_after, allowance_before - transfer_value)
        self.assertEqual(admin_balance_after, admin_balance_before - transfer_value)
        self.assertEqual(user_balance_after, user_balance_before + transfer_value)

    def test_erc20_transferFrom_beyond_approve(self):
        transfer_value = 10_000_000
        erc20 = self.wrapper.erc20_interface()

        with self.assertRaisesRegex(Exception, "ERC20: insufficient allowance"):
            erc20.functions.transferFrom(self.admin.address, self.user.address, transfer_value).build_transaction(
                {'from': self.user.address}
            )

    def test_erc20_transferFrom_out_of_bounds(self):
        transfer_value = 0xFFFF_FFFF_FFFF_FFFF + 1
        approve_value = transfer_value + 1
        erc20 = self.wrapper.erc20_interface()

        tx = erc20.functions.approve(self.user.address, approve_value).build_transaction({'from': self.admin.address})
        tx = self.proxy.sign_send_wait_transaction(self.admin, tx)
        self.assertEqual(tx.tx_receipt.status, 1)

        with self.assertRaisesRegex(Exception, "ERC20: transfer amount exceeds uint64 max"):
            erc20.functions.transferFrom(self.admin.address, self.user.address, transfer_value).build_transaction(
                {'from': self.user.address}
            )

    def test_erc20_approveSolana(self):
        delegate = SolAccount()
        approve_value = 1000
        erc20 = self.wrapper.erc20_interface()

        tx = erc20.functions.approveSolana(bytes(delegate.public_key), approve_value).build_transaction(
            {'from': self.admin.address})
        tx = self.proxy.sign_send_wait_transaction(self.admin, tx)
        self.assertEqual(tx.tx_receipt.status, 1)

        accounts = self.solana_client.get_token_accounts_by_delegate(
            delegate.public_key,
            TokenAccountOpts(mint=self.token.pubkey), commitment=Processed
        )
        accounts = list(map(lambda a: a.pubkey, accounts.value))

        self.assertGreaterEqual(len(accounts), 1)

class Test_erc20ForSplMintable_contract(Test_erc20ForSpl_contract):

    @classmethod
    def setUpClass(cls):
        cls.proxy = Proxy()
        cls.admin = cls.proxy.create_signer_account('issues/neonlabsorg/proxy-model.py/197/admin')
        cls.user = cls.proxy.create_signer_account('issues/neonlabsorg/proxy-model.py/197/user')
        cls.config = Config()

        print("\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/197")
        print('admin.key:', cls.admin.key.hex())
        print('admin.address:', cls.admin.address)
        print('user.key:', cls.user.key.hex())
        print('user.address:', cls.user.address)

        cls.init_solana_client(cls)
        cls.deploy_erc20_wrapper_contract(cls)

    def deploy_erc20_wrapper_contract(self):
        self.wrapper = ERC20Wrapper(
            self.proxy.web3, NAME, SYMBOL,
            None, self.admin,
            None,
            self.config.evm_loader_id
        )
        self.wrapper.deploy_mintable_wrapper(NAME, SYMBOL, DECIMALS, self.admin.address)

        nonce = self.proxy.conn.get_transaction_count(self.admin.address)
        tx = self.wrapper.erc20.functions.mint(self.admin.address, 1000000000).build_transaction({'nonce': nonce, 'from': self.admin.address})
        tx = self.proxy.conn.account.sign_transaction(tx, self.admin.key)
        tx_hash = self.proxy.conn.send_raw_transaction(tx.rawTransaction)
        tx_receipt = self.proxy.conn.wait_for_transaction_receipt(tx_hash)
        assert(tx_receipt.status == 1)

        mint_account = PublicKey(self.wrapper.erc20.functions.findMintAccount().call())
        self.token = SplToken(
            self.solana_client,
            mint_account, TOKEN_PROGRAM_ID,
            self.solana_account
        )

        print(f"Mint account {mint_account}")


if __name__ == '__main__':
    unittest.main()
