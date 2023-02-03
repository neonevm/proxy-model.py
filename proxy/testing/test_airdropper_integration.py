import json
import unittest

from time import sleep
from unittest import TestCase

from solana.rpc.api import Client as SolanaClient
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts
from solders.system_program import ID as SYS_PROGRAM_ID
from solana.transaction import Transaction

from spl.token.client import Token as SplToken
from spl.token.constants import TOKEN_PROGRAM_ID
import spl.token.instructions as SplTokenInstrutions

from ..common_neon.metaplex import create_metadata_instruction_data,create_metadata_instruction
from ..common_neon.environment_data import EVM_LOADER_ID
from ..common_neon.constants import ACCOUNT_SEED_VERSION
from proxy.common_neon.solana_tx import SolAccountMeta, SolTxIx, SolAccount, SolPubKey
from proxy.common_neon.solana_tx_legacy import SolLegacyTx
from proxy.common_neon.neon_instruction import create_account_layout
from proxy.common_neon.erc20_wrapper import ERC20Wrapper
from proxy.common_neon.config import Config
from proxy.common_neon.elf_params import ElfParams
from proxy.common_neon.constants import COMPUTE_BUDGET_ID

from proxy.testing.testing_helpers import Proxy
from proxy.testing.solana_utils import EvmLoader, OperatorAccount, wallet_path


MAX_AIRDROP_WAIT_TIME = 45
EVM_LOADER_ID = SolPubKey.from_string(EVM_LOADER_ID)
NAME = 'TestToken'
SYMBOL = 'TST'


# Helper function calculating solana address and nonce from given NEON(Ethereum) address
def get_evm_loader_account_address(eth_address: str):
    eth_addressbytes = bytes.fromhex(eth_address[2:])
    return SolPubKey.find_program_address([ACCOUNT_SEED_VERSION, eth_addressbytes], EVM_LOADER_ID)


class TestAirdropperIntegration(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.proxy = Proxy()
        cls.admin = cls.proxy.create_signer_account('neonlabsorg/proxy-model.py/issues/344/admin20')
        cls.create_token_mint(cls)
        cls.deploy_erc20_wrapper_contract(cls)
        cls.acc_num = 0
        cls.config = Config()
        cls.elf_params = ElfParams()
        cls.loader = EvmLoader(OperatorAccount(wallet_path()), str(cls.config.evm_loader_id))

    def create_token_mint(self):
        self.solana_client = SolanaClient(Config().solana_url)

        with open("proxy/operator-keypairs/id2.json") as f:
            d = json.load(f)
        self.mint_authority = SolAccount.from_bytes(bytes(d))
        print('Account: ', self.mint_authority.pubkey())
        self.solana_client.request_airdrop(self.mint_authority.pubkey(), 1000_000_000_000)

        for i in range(20):
            sleep(1)
            balance = self.solana_client.get_balance(self.mint_authority.pubkey()).value
            if balance == 0:
                continue

            try:
                self.token = SplToken.create_mint(
                    self.solana_client,
                    self.mint_authority,
                    self.mint_authority.pubkey(),
                    9,
                    TOKEN_PROGRAM_ID,
                )
                print(
                    'create_token_mint mint, SolanaAccount: ',
                    self.solana_client.get_account_info(self.mint_authority.pubkey())
                )

                print(f'Created new token mint: {self.token.pubkey}')

                metadata = create_metadata_instruction_data(NAME, SYMBOL, 0, ())
                txn = Transaction()
                txn.add(
                    create_metadata_instruction(
                        metadata,
                        self.mint_authority.pubkey(),
                        self.token.pubkey,
                        self.mint_authority.pubkey(),
                        self.mint_authority.pubkey(),
                    )
                )
                self.solana_client.send_transaction(txn, self.mint_authority, opts=TxOpts(preflight_commitment=Confirmed, skip_confirmation=False))

                return
            except (Exception,):
                continue
        self.assertTrue(False)

    def deploy_erc20_wrapper_contract(self):
        self.wrapper = ERC20Wrapper(
            self.proxy.web3, NAME, SYMBOL,
            self.token, self.admin,
            self.mint_authority,
            EVM_LOADER_ID
        )
        self.wrapper.deploy_wrapper()

    @staticmethod
    def create_account_instruction(eth_address: str, payer: SolPubKey):
        dest_address_solana, nonce = get_evm_loader_account_address(eth_address)
        return SolTxIx(
            program_id=EVM_LOADER_ID,
            data=create_account_layout(bytes.fromhex(eth_address[2:])),
            accounts=[
                SolAccountMeta(pubkey=payer, is_signer=True, is_writable=True),
                SolAccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                SolAccountMeta(pubkey=dest_address_solana, is_signer=False, is_writable=True),
            ])

    def create_sol_account(self):
        account = SolAccount()
        print(f"New solana account created: {account.pubkey()}. Airdropping...")
        self.solana_client.request_airdrop(account.pubkey(), 1000_000_000_000, Confirmed)
        return account

    def create_token_account(self, owner: SolPubKey, mint_amount: int):
        new_token_account = self.wrapper.create_associated_token_account(owner, self.mint_authority)
        self.wrapper.mint_to(new_token_account, mint_amount)
        return new_token_account

    def create_eth_account(self):
        self.acc_num += 1
        account = self.proxy.create_account(f'neonlabsorg/proxy-model.py/issues/344/eth_account{self.acc_num}')
        print(f"NEON account created: {account.address}")
        return account

    def test_success_airdrop_simple_case(self):
        from_owner = self.create_sol_account()
        mint_amount = 1000_000_000_000
        from_spl_token_acc = self.create_token_account(from_owner.pubkey(), mint_amount)
        signer_account = self.create_eth_account()
        to_neon_acc = self.create_eth_account()

        print(f'        OWNER {from_owner.pubkey()}')
        print(f'            SPL TOKEN ACC {from_spl_token_acc}')

        self.assertEqual(self.wrapper.get_balance(from_spl_token_acc), mint_amount)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc.address), 0)

        transfer_amount = 123456
        tx = SolLegacyTx(instructions=[
            SolTxIx(
                program_id=COMPUTE_BUDGET_ID,
                accounts=[],
                data=bytes.fromhex("01") + self.elf_params.neon_heap_frame.to_bytes(4, "little")
            ),
            SolTxIx(
                program_id=COMPUTE_BUDGET_ID,
                accounts=[],
                data=bytes.fromhex("02") + self.elf_params.neon_compute_units.to_bytes(4, "little")
            ),
            self.create_account_instruction(signer_account.address, from_owner.pubkey())
        ])
        tx.add(self.create_account_instruction(to_neon_acc.address, from_owner.pubkey()))
        tx.add(
            SplTokenInstrutions.approve(SplTokenInstrutions.ApproveParams(
                program_id=self.token.program_id,
                source=from_spl_token_acc,
                delegate=self.wrapper.get_auth_account_address(signer_account.address),
                owner=from_owner.pubkey(),
                amount=transfer_amount,
                signers=[],
            ))
        )
        tx.add(
            self.wrapper.create_claim_to_instruction(
                owner=from_owner.pubkey(),
                from_acc=from_spl_token_acc,
                to_acc=to_neon_acc,
                amount=transfer_amount,
                signer_acc=signer_account,
            ).make_tx_exec_from_data_ix()
        )

        opts = TxOpts(skip_preflight=True, skip_confirmation=False)
        print(self.solana_client.send_transaction(tx.low_level_tx, from_owner, opts=opts))

        self.assertEqual(self.wrapper.get_balance(from_spl_token_acc), mint_amount - transfer_amount)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc.address), transfer_amount)

        eth_balance = self.proxy.conn.get_balance(to_neon_acc.address)
        print("NEON balance before is: ", eth_balance)

        wait_time = 0
        while wait_time < MAX_AIRDROP_WAIT_TIME:
            eth_balance = self.proxy.conn.get_balance(to_neon_acc.address)
            balance_ready = 0 < eth_balance < 10 * pow(10, 18)
            if balance_ready:
                break
            sleep(1)
            wait_time += 1
        print(f"Wait time for simple SolLegacyTx (1 airdrop): {wait_time}")

        eth_balance = self.proxy.conn.get_balance(to_neon_acc.address)
        print("NEON balance is: ", eth_balance)
        self.assertTrue(0 < eth_balance < 10 * pow(10, 18))  # 10 NEON is a max airdrop amount

    @unittest.skip('Test case is not applicable after introducing ERC20-for-SPL. Postponed for a better times')
    def test_success_airdrop_complex_case(self):
        from_owner = self.create_sol_account()
        mint_amount = 1000_000_000_000
        from_spl_token_acc = self.create_token_account(from_owner.pubkey(), mint_amount)
        to_neon_acc1 = self.create_eth_account()
        to_neon_acc2 = self.create_eth_account()

        self.assertEqual(self.wrapper.get_balance(from_spl_token_acc), mint_amount)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc1.address), 0)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc2.address), 0)

        transfer_amount1 = 123456
        transfer_amount2 = 654321
        tx = SolLegacyTx(instructions=[
            SolTxIx(
                program_id=COMPUTE_BUDGET_ID,
                accounts=[],
                data=bytes.fromhex("01") + self.elf_params.neon_heap_frame.to_bytes(4, "little")
            ),
            SolTxIx(
                program_id=COMPUTE_BUDGET_ID,
                accounts=[],
                data=bytes.fromhex("02") + self.elf_params.neon_compute_units.to_bytes(4, "little")
            ),
            self.create_account_instruction(to_neon_acc1.address, from_owner.pubkey())
        ])
        tx.add(self.create_account_instruction(to_neon_acc2.address, from_owner.pubkey()))
        tx.add(SplTokenInstrutions.approve(SplTokenInstrutions.ApproveParams(
            program_id=self.token.program_id,
            source=from_spl_token_acc,
            delegate=self.wrapper.get_auth_account_address(to_neon_acc1.address),
            owner=from_owner.pubkey(),
            amount=transfer_amount1,
            signers=[],
        )))
        tx.add(SplTokenInstrutions.approve(SplTokenInstrutions.ApproveParams(
            program_id=self.token.program_id,
            source=from_spl_token_acc,
            delegate=self.wrapper.get_auth_account_address(to_neon_acc2.address),
            owner=from_owner.pubkey(),
            amount=transfer_amount2,
            signers=[],
        )))
        claim_instr1 = self.wrapper.create_claim_instruction(
            owner=from_owner.pubkey(),
            from_acc=from_spl_token_acc,
            to_acc=to_neon_acc1,
            amount=transfer_amount1,
        )
        tx.add(claim_instr1.make_tx_exec_from_data_ix())
        claim_instr2 = self.wrapper.create_claim_instruction(
            owner=from_owner.pubkey(),
            from_acc=from_spl_token_acc,
            to_acc=to_neon_acc2,
            amount=transfer_amount2,
        )
        tx.add(claim_instr2.make_tx_exec_from_data_ix())

        opts = TxOpts(skip_preflight=True, skip_confirmation=False)
        print(self.solana_client.send_transaction(tx.low_level_tx, from_owner, opts=opts))

        self.assertEqual(self.wrapper.get_balance(from_spl_token_acc), mint_amount - transfer_amount1 - transfer_amount2)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc1.address), transfer_amount1)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc2.address), transfer_amount2)

        wait_time = 0
        while wait_time < MAX_AIRDROP_WAIT_TIME:
            eth_balance1 = self.proxy.conn.get_balance(to_neon_acc1.address)
            eth_balance2 = self.proxy.conn.get_balance(to_neon_acc2.address)
            balance1_ready = 0 < eth_balance1 < 10 * pow(10, 18)
            balance2_ready = 0 < eth_balance2 < 10 * pow(10, 18)
            if balance1_ready and balance2_ready:
                break
            sleep(1)
            wait_time += 1
        print(f"Wait time for complex SolLegacyTx (2 airdrops): {wait_time}")

        eth_balance1 = self.proxy.conn.get_balance(to_neon_acc1.address)
        eth_balance2 = self.proxy.conn.eth.get_balance(to_neon_acc2.address)
        print("NEON balance 1 is: ", eth_balance1)
        print("NEON balance 2 is: ", eth_balance2)
        self.assertTrue(0 < eth_balance1 < 10 * pow(10, 18))  # 10 NEON is a max airdrop amount
        self.assertTrue(0 < eth_balance2 < 10 * pow(10, 18))  # 10 NEON is a max airdrop amount

    def test_no_airdrop(self):
        from_owner = self.create_sol_account()
        mint_amount = 1000_000_000_000
        from_spl_token_acc = self.create_token_account(from_owner.pubkey(), mint_amount)
        to_neon_acc = self.create_eth_account()

        initial_balance = 1_000
        # Create account before input liquidity (should not cause airdrop)
        self.proxy.request_airdrop(to_neon_acc.address, initial_balance)
        sleep(15)

        self.assertEqual(self.wrapper.get_balance(from_spl_token_acc), mint_amount)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc.address), 0)  # Destination-acc ERC20-Token balance is 0
        self.assertEqual(self.proxy.conn.get_balance(to_neon_acc.address), initial_balance * 10**18)  # Destination-acc Neon balance is initial

        transfer_amount = 123456
        tx = SolLegacyTx(instructions=[
            SolTxIx(
                program_id=COMPUTE_BUDGET_ID,
                accounts=[],
                data=bytes.fromhex("01") + self.elf_params.neon_heap_frame.to_bytes(4, "little")
            ),
            SolTxIx(
                program_id=COMPUTE_BUDGET_ID,
                accounts=[],
                data=bytes.fromhex("02") + self.elf_params.neon_compute_units.to_bytes(4, "little")
            ),
            SplTokenInstrutions.approve(SplTokenInstrutions.ApproveParams(
                program_id=self.token.program_id,
                source=from_spl_token_acc,
                delegate=self.wrapper.get_auth_account_address(to_neon_acc.address),
                owner=from_owner.pubkey(),
                amount=transfer_amount,
                signers=[],
            ))
        ])
        tx.add(
            self.wrapper.create_claim_instruction(
                owner=from_owner.pubkey(),
                from_acc=from_spl_token_acc,
                to_acc=to_neon_acc,
                amount=transfer_amount,
            ).make_tx_exec_from_data_ix()
        )

        opts = TxOpts(skip_preflight=True, skip_confirmation=False)
        print(self.solana_client.send_transaction(tx.low_level_tx, from_owner, opts=opts))

        sleep(15)
        self.assertEqual(self.wrapper.get_balance(from_spl_token_acc), mint_amount - transfer_amount)
        self.assertEqual(self.wrapper.get_balance(to_neon_acc.address), transfer_amount)
        eth_balance = self.proxy.conn.get_balance(to_neon_acc.address)
        print("NEON balance is: ", eth_balance)
        # Balance should not change because airdropper should not handle this transaction
        self.assertEqual(eth_balance, initial_balance * 10**18)
