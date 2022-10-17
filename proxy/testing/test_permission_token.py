import unittest

from solana.rpc.api import Client as SolanaClient
from solana.rpc.commitment import Confirmed

from proxy.common_neon.permission_token import PermissionToken
from proxy.common_neon.solana_interactor import SolInteractor
from proxy.common_neon.solana_tx import SolPubKey, SolAccount
from proxy.common_neon.elf_params import ElfParams
from proxy.common_neon.config import Config
from proxy.testing.testing_helpers import Proxy


class TestPermissionToken(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        config = Config()
        cls.solana = SolInteractor(config, config.solana_url)
        cls.mint_authority_file = "/spl/bin/evm_loader-keypair.json"
        cls.proxy = Proxy()
        cls.eth_account = cls.proxy.create_signer_account('https://github.com/neonlabsorg/proxy-model.py/issues/468')

        cls.payer = SolAccount()
        client = SolanaClient(config.solana_url)
        client.request_airdrop(cls.payer.public_key, 1000_000_000_000, Confirmed)
        cls.allowance_token = PermissionToken(config, cls.solana, SolPubKey(ElfParams().allowance_token_addr))
        cls.denial_token = PermissionToken(config, cls.solana, SolPubKey(ElfParams().denial_token_addr))

    def test_mint_permission_tokens(self):
        """
        Should receive all permission tokens minted by authority
        """
        new_acc = self.proxy.create_account(f'test_mint_permission_tokens')
        allowance_amount = 1234
        denial_amount = 4321
        self.allowance_token.mint_to(allowance_amount, new_acc.address, self.mint_authority_file, self.payer)
        self.denial_token.mint_to(denial_amount, new_acc.address, self.mint_authority_file, self.payer)
        self.assertEqual(self.allowance_token.get_balance(new_acc.address), allowance_amount)
        self.assertEqual(self.denial_token.get_balance(new_acc.address), denial_amount)
