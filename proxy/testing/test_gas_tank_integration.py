import json
import unittest

from time import sleep
from unittest import TestCase
from typing import Dict, Any

from solana.rpc.api import Client as RPCSolClient
from solana.rpc.commitment import Confirmed as RPCSolConfirmed
from solders.system_program import ID as SYS_PROGRAM_ID

from spl.token.client import Token as SplToken
from spl.token.constants import TOKEN_PROGRAM_ID
import spl.token.instructions as SplTokenInstrutions

from proxy.common_neon.metaplex import create_metadata_instruction_data, create_metadata_instruction
from proxy.common_neon.solana_tx import SolAccountMeta, SolTxIx, SolAccount, SolPubKey
from proxy.common_neon.neon_instruction import create_account_layout
from proxy.common_neon.erc20_wrapper import ERC20Wrapper
from proxy.common_neon.config import Config
from proxy.common_neon.elf_params import ElfParams
from proxy.common_neon.address import neon_2program
from proxy.common_neon.constants import COMPUTE_BUDGET_ID
from proxy.common_neon.solana_tx_legacy import SolLegacyTx

from proxy.testing.testing_helpers import Proxy, SolClient, NeonLocalAccount


MAX_ZERO_GAS_PRICE_WAIT_TIME = 15
NAME = 'TestToken'
SYMBOL = 'TST'


class FakeConfig(Config):
    @property
    def fuzz_fail_pct(self) -> int:
        return 0


class TestGasTankIntegration(TestCase):
    proxy: Proxy
    admin: NeonLocalAccount
    solana: SolClient
    config: Config
    mint_authority: SolAccount
    token: SplToken
    erc20_for_spl: ERC20Wrapper
    solana: SolClient

    @classmethod
    def setUpClass(cls):
        cls.proxy = Proxy()
        cls.admin = cls.proxy.create_signer_account('neonlabsorg/proxy-model.py/issues/344/admin20')
        cls.config = FakeConfig()
        cls.solana = SolClient(cls.config)
        cls.create_token_mint()
        cls.deploy_erc20_for_spl()
        cls.acc_num = 0
        cls.elf_params = ElfParams()

    @classmethod
    def create_token_mint(cls):
        sol_client = RPCSolClient(Config().solana_url, commitment=RPCSolConfirmed)

        with open("proxy/operator-keypairs/id2.json") as f:
            d = json.load(f)
        cls.mint_authority = SolAccount.from_bytes(bytes(d))
        print('Account: ', cls.mint_authority.pubkey())
        cls.solana.request_airdrop(cls.mint_authority.pubkey(), 1000_000_000_000)
        for i in range(20):
            sleep(1)
            balance = cls.solana.get_sol_balance(cls.mint_authority.pubkey())
            if balance == 0:
                continue

        cls.token = SplToken.create_mint(
            sol_client,
            cls.mint_authority,
            cls.mint_authority.pubkey(),
            9,
            TOKEN_PROGRAM_ID,
        )
        print(
            'create_token_mint mint, SolanaAccount: ',
            cls.solana.get_account_info(cls.mint_authority.pubkey())
        )

        print(f'Created new token mint: {cls.token.pubkey}')

        metadata = create_metadata_instruction_data(NAME, SYMBOL)
        tx = SolLegacyTx(
            name='CreateMetadata',
            ix_list=[
                create_metadata_instruction(
                    metadata,
                    cls.mint_authority.pubkey(),
                    cls.token.pubkey,
                    cls.mint_authority.pubkey(),
                    cls.mint_authority.pubkey(),
                )
            ]
        )
        cls.solana.send_tx(tx, cls.mint_authority)

    @classmethod
    def deploy_erc20_for_spl(cls):
        cls.erc20_for_spl = ERC20Wrapper(
            cls.config,
            cls.proxy.web3,
            NAME,
            SYMBOL,
            cls.token,
            cls.admin,
            cls.mint_authority
        )
        cls.erc20_for_spl.deploy_wrapper()

    @classmethod
    def create_account_instruction(cls, neon_address: str, payer: SolPubKey):
        dest_address_solana, nonce = neon_2program(cls.config.evm_program_id, neon_address)
        return SolTxIx(
            program_id=cls.config.evm_program_id,
            data=create_account_layout(bytes.fromhex(neon_address[2:])),
            accounts=[
                SolAccountMeta(pubkey=payer, is_signer=True, is_writable=True),
                SolAccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                SolAccountMeta(pubkey=dest_address_solana, is_signer=False, is_writable=True),
            ]
        )

    def create_sol_account(self):
        account = SolAccount()
        print(f"New solana account created: {account.pubkey()}. Airdropping SOL...")
        self.solana.request_airdrop(account.pubkey(), 1000_000_000_000)
        return account

    def create_token_account(self, owner: SolPubKey, mint_amount: int):
        new_token_account = self.erc20_for_spl.create_associated_token_account(owner)
        print(f'associated token account: {new_token_account}')
        self.erc20_for_spl.mint_to(new_token_account, mint_amount)
        return new_token_account

    def create_eth_account(self):
        self.acc_num += 1
        account = self.proxy.create_account(f'neonlabsorg/proxy-model.py/issues/344/eth_account{self.acc_num}')
        print(f"NEON account created: {account.address}")
        return account

    def build_tx(self, name: str, ix_list) -> SolLegacyTx:
        return SolLegacyTx(
            name=name,
            ix_list=[
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
            ] + ix_list
        )

    def neon_gas_price_impl(self, param: Dict[str, Any]) -> int:
        gas_price = self.proxy.web3.neon.neon_gasPrice(param)
        return int(gas_price[2:], 16)

    def neon_gas_price(self, account: str) -> int:
        gas = 1_000_000
        big_gas = 30_000_000

        gas_price = self.neon_gas_price_impl({'from': account, 'gas': gas})
        print(f'neon_gasPrice(from={account}, gas={gas}) = {gas_price}')
        if gas_price != 0:
            return gas_price

        big_nonce = 6
        for nonce in range(0, big_nonce):
            zero_gas_price = self.neon_gas_price_impl({'from': account, 'nonce': nonce, 'gas': gas})
            self.assertEqual(zero_gas_price, 0)

            big_gas_price = self.neon_gas_price_impl({'from': account, 'nonce': nonce, 'gas': big_gas})
            self.assertNotEqual(big_gas_price, 0)

        big_gas_price = self.neon_gas_price_impl({'from': account, 'nonce': big_nonce, 'gas': gas})
        self.assertNotEqual(big_gas_price, 0)

        big_gas_price = self.neon_gas_price_impl({'from': account, 'nonce': big_nonce, 'gas': big_gas})
        self.assertNotEqual(big_gas_price, 0)

        return gas_price

    def test_success_gas_less_simple_case(self):
        from_owner = self.create_sol_account()
        mint_amount = 1000_000_000_000
        from_spl_token_acc = self.create_token_account(from_owner.pubkey(), mint_amount)
        signer_acct = self.create_eth_account()
        to_neon_acct = self.create_eth_account()

        print(f'        OWNER {from_owner.pubkey()}')
        print(f'            SPL TOKEN ACC {from_spl_token_acc}')

        self.assertEqual(self.erc20_for_spl.get_balance(from_spl_token_acc), mint_amount)
        self.assertEqual(self.erc20_for_spl.get_balance(to_neon_acct.address), 0)

        transfer_amount = 123456
        tx = self.build_tx(
            name='SimpleCase',
            ix_list=[
                self.create_account_instruction(signer_acct.address, from_owner.pubkey()),
                self.create_account_instruction(to_neon_acct.address, from_owner.pubkey()),
                SplTokenInstrutions.approve(SplTokenInstrutions.ApproveParams(
                    program_id=self.token.program_id,
                    source=from_spl_token_acc,
                    delegate=self.erc20_for_spl.get_auth_account_address(signer_acct.address),
                    owner=from_owner.pubkey(),
                    amount=transfer_amount,
                    signers=[],
                )),
                self.erc20_for_spl.create_claim_to_ix(
                    owner=from_owner.pubkey(),
                    from_acct=from_spl_token_acc,
                    to_acct=to_neon_acct,
                    amount=transfer_amount,
                    signer_acct=signer_acct,
                ).make_tx_exec_from_data_ix()
            ]
        )

        self.solana.send_tx(tx, from_owner)

        self.assertEqual(self.erc20_for_spl.get_balance(from_spl_token_acc), mint_amount - transfer_amount)
        self.assertEqual(self.erc20_for_spl.get_balance(to_neon_acct.address), transfer_amount)

        gas_price = 1
        wait_time = 0
        while wait_time < MAX_ZERO_GAS_PRICE_WAIT_TIME:
            gas_price = self.neon_gas_price(to_neon_acct.address)
            if gas_price == 0:
                return

            sleep(1)
            wait_time += 1
        print(f"Wait time for simple SolLegacyTx (1 zero-gas-price): {wait_time}")
        self.assertEqual(gas_price, 0)

    def test_success_gas_less_complex_case(self):
        from_owner = self.create_sol_account()
        mint_amount = 1000_000_000_000
        from_spl_token_acct = self.create_token_account(from_owner.pubkey(), mint_amount)
        to_neon_acct1 = self.create_eth_account()
        to_neon_acct2 = self.create_eth_account()
        signer_acct = self.create_eth_account()

        self.assertEqual(self.erc20_for_spl.get_balance(from_spl_token_acct), mint_amount)
        self.assertEqual(self.erc20_for_spl.get_balance(to_neon_acct1.address), 0)
        self.assertEqual(self.erc20_for_spl.get_balance(to_neon_acct2.address), 0)

        tx = self.build_tx(
            name='CreateSignerComplexCase',
            ix_list=[
                self.create_account_instruction(signer_acct.address, from_owner.pubkey()),
            ]
        )
        self.solana.send_tx(tx, from_owner)

        transfer_amount1 = 123456
        transfer_amount2 = 654321
        tx = self.build_tx(
            name='ComplexCase',
            ix_list=[
                self.create_account_instruction(to_neon_acct1.address, from_owner.pubkey()),
                self.create_account_instruction(to_neon_acct2.address, from_owner.pubkey()),
                SplTokenInstrutions.approve(SplTokenInstrutions.ApproveParams(
                    program_id=self.token.program_id,
                    source=from_spl_token_acct,
                    delegate=self.erc20_for_spl.get_auth_account_address(signer_acct.address),
                    owner=from_owner.pubkey(),
                    amount=transfer_amount1+transfer_amount2,
                    signers=[],
                )),
                self.erc20_for_spl.create_claim_to_ix(
                    owner=from_owner.pubkey(),
                    from_acct=from_spl_token_acct,
                    to_acct=to_neon_acct1,
                    amount=transfer_amount1,
                    signer_acct=signer_acct,
                    nonce=0
                ).make_tx_exec_from_data_ix(),
                self.erc20_for_spl.create_claim_to_ix(
                    owner=from_owner.pubkey(),
                    from_acct=from_spl_token_acct,
                    to_acct=to_neon_acct2,
                    amount=transfer_amount2,
                    signer_acct=signer_acct,
                    nonce=1
                ).make_tx_exec_from_data_ix()
            ]
        )
        self.solana.send_tx(tx, from_owner)

        self.assertEqual(
            self.erc20_for_spl.get_balance(from_spl_token_acct),
            mint_amount - transfer_amount1 - transfer_amount2
        )
        self.assertEqual(self.erc20_for_spl.get_balance(to_neon_acct1.address), transfer_amount1)
        self.assertEqual(self.erc20_for_spl.get_balance(to_neon_acct2.address), transfer_amount2)

        gas_price1 = 1
        gas_price2 = 2
        wait_time = 0
        while wait_time < MAX_ZERO_GAS_PRICE_WAIT_TIME:
            gas_price1 = self.neon_gas_price(to_neon_acct1.address)
            gas_price2 = self.neon_gas_price(to_neon_acct2.address)
            if (gas_price1 == 0) and (gas_price2 == 0):
                return

            sleep(1)
            wait_time += 1

        print(f"Wait time for complex SolLegacyTx (2 gas-less): {wait_time}")
        self.assertEqual(gas_price1, 0)
        self.assertEqual(gas_price2, 0)

    def test_no_gas_less_tx(self):
        from_owner = self.create_sol_account()
        mint_amount = 1000_000_000_000
        from_spl_token_acc = self.create_token_account(from_owner.pubkey(), mint_amount)
        to_neon_acct = self.create_eth_account()
        signer_acct = self.create_eth_account()

        initial_balance = 1_000
        # Create account before input liquidity (should not cause gas-less tx)
        self.proxy.request_airdrop(to_neon_acct.address, initial_balance)
        sleep(2)

        self.assertEqual(self.erc20_for_spl.get_balance(from_spl_token_acc), mint_amount)
        # Destination-acc ERC20-Token balance is 0
        self.assertEqual(self.erc20_for_spl.get_balance(to_neon_acct.address), 0)
        # Destination-acc Neon balance is initial
        self.assertEqual(self.proxy.conn.get_balance(to_neon_acct.address), initial_balance * 10**18)

        transfer_amount = 123456
        tx = self.build_tx(
            name='NoGasTankAllowance',
            ix_list=[
                self.create_account_instruction(signer_acct.address, from_owner.pubkey()),
                SplTokenInstrutions.approve(SplTokenInstrutions.ApproveParams(
                    program_id=self.token.program_id,
                    source=from_spl_token_acc,
                    delegate=self.erc20_for_spl.get_auth_account_address(signer_acct.address),
                    owner=from_owner.pubkey(),
                    amount=transfer_amount,
                    signers=[],
                )),
                self.erc20_for_spl.create_claim_to_ix(
                    owner=from_owner.pubkey(),
                    from_acct=from_spl_token_acc,
                    to_acct=to_neon_acct,
                    amount=transfer_amount,
                    signer_acct=signer_acct,
                ).make_tx_exec_from_data_ix()
            ]
        )

        self.solana.send_tx(tx, from_owner)

        wait_time = 0
        while wait_time < MAX_ZERO_GAS_PRICE_WAIT_TIME:
            gas_price = self.neon_gas_price(to_neon_acct.address)
            if gas_price == 0:
                break

            sleep(1)
            wait_time += 1

        self.assertEqual(self.erc20_for_spl.get_balance(from_spl_token_acc), mint_amount - transfer_amount)
        self.assertEqual(self.erc20_for_spl.get_balance(to_neon_acct.address), transfer_amount)

        gas_price = self.neon_gas_price(to_neon_acct.address)
        self.assertNotEqual(gas_price, 0)

    @unittest.skip('claimTo fails SolTx')
    def test_failed_gas_less_tx(self):
        """Should fail because approve is given to wrong account"""
        from_owner = self.create_sol_account()
        mint_amount = 1000_000_000_000
        from_spl_token_acc = self.create_token_account(from_owner.pubkey(), mint_amount)
        signer_acct = self.create_eth_account()
        to_neon_acct = self.create_eth_account()

        transfer_amount = 6534
        tx = self.build_tx(
            name='FailedTxCase',
            ix_list=[
                self.create_account_instruction(to_neon_acct.address, from_owner.pubkey()),
                SplTokenInstrutions.approve(SplTokenInstrutions.ApproveParams(
                    program_id=self.token.program_id,
                    source=from_spl_token_acc,
                    delegate=self.erc20_for_spl.get_auth_account_address(to_neon_acct.address),
                    owner=from_owner.pubkey(),
                    amount=transfer_amount,
                    signers=[],
                )),
                self.create_account_instruction(signer_acct.address, from_owner.pubkey()),
                self.erc20_for_spl.create_claim_to_ix(
                    owner=from_owner.pubkey(),
                    from_acct=from_spl_token_acc,
                    to_acct=to_neon_acct,
                    amount=transfer_amount,
                    signer_acct=signer_acct,
                ).make_tx_exec_from_data_ix()
            ]
        )
        self.solana.send_tx(tx, from_owner, skip_preflight=True)

        self.assertEqual(self.erc20_for_spl.get_balance(from_spl_token_acc), mint_amount)
        self.assertEqual(self.erc20_for_spl.get_balance(to_neon_acct.address), 0)

        gas_price = 1
        wait_time = 0
        while wait_time < MAX_ZERO_GAS_PRICE_WAIT_TIME:
            gas_price = self.neon_gas_price(to_neon_acct.address)
            if gas_price != 0:
                break

            sleep(1)
            wait_time += 1
        self.assertNotEqual(gas_price, 0)
