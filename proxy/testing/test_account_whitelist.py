import unittest
from proxy.common_neon.solana_interactor import SolInteractor
from proxy.common_neon.account_whitelist import AccountWhitelist
from proxy.common_neon.solana_transaction import SolAccount
from proxy.common_neon.config import Config
from solana.rpc.api import Client as SolanaClient
from solana.rpc.commitment import Commitment
from unittest.mock import Mock, MagicMock, patch, call


Confirmed = Commitment('confirmed')


class FakeConfig(Config):
    @property
    def account_permission_update_int(self) -> int:
        return 10


class TestAccountWhitelist(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = config = FakeConfig()
        cls.solana = solana = SolInteractor(config, config.solana_url)
        cls.mint_authority_file = "/spl/bin/evm_loader-keypair.json"
        cls.payer = payer = SolAccount()
        client = SolanaClient(config.solana_url)
        client.request_airdrop(payer.public_key(), 1000_000_000_000, Confirmed)

        cls.testee = testee = AccountWhitelist(config, solana)

        mock_allowance_token = Mock()
        mock_allowance_token.get_token_account_address = MagicMock()
        mock_allowance_token.mint_to = MagicMock()
        testee.allowance_token = mock_allowance_token

        mock_denial_token = Mock()
        mock_denial_token.get_token_account_address = MagicMock()
        mock_denial_token.mint_to = MagicMock()
        testee.denial_token = mock_denial_token

    def tearDown(self) -> None:
        self.testee.allowance_token.get_token_account_address.reset_mock()
        self.testee.allowance_token.mint_to.reset_mock()
        self.testee.denial_token.get_token_account_address.reset_mock()
        self.testee.denial_token.mint_to.reset_mock()
        self.testee.account_cache = {}

    @patch.object(SolInteractor, 'get_token_account_balance_list')
    def test_grant_permissions_negative_difference(self, mock_get_token_account_balance_list):
        """
        Should mint allowance token - negative differenct
        """
        allowance_balance = 100
        denial_balance = 103
        diff = allowance_balance - denial_balance
        min_balance = 3
        expected_mint = min_balance - diff
        ether_address = 'Ethereum-Address'
        mint_authority_file = "/spl/bin/evm_loader-keypair.json"

        mock_get_token_account_balance_list.side_effect = [[allowance_balance, denial_balance]]

        self.assertTrue(self.testee.grant_permissions(ether_address, min_balance, self.payer))

        self.testee.allowance_token.get_token_account_address.assert_called_once_with(ether_address)
        self.testee.denial_token.get_token_account_address.assert_called_once_with(ether_address)
        self.testee.allowance_token.mint_to.assert_called_once_with(
            expected_mint, ether_address, mint_authority_file, self.payer)

    @patch.object(SolInteractor, 'get_token_account_balance_list')
    def test_grant_permissions_positive_difference(self, mock_get_token_account_balance_list):
        """
        Should NOT mint allowance token - positive difference
        """
        allowance_balance = 103
        denial_balance = 100
        min_balance = 1
        ether_address = 'Ethereum-Address'

        mock_get_token_account_balance_list.side_effect = [[allowance_balance, denial_balance]]

        self.assertTrue(self.testee.grant_permissions(ether_address, min_balance, self.payer))

        self.testee.allowance_token.get_token_account_address.assert_called_once_with(ether_address)
        self.testee.denial_token.get_token_account_address.assert_called_once_with(ether_address)
        self.testee.allowance_token.mint_to.assert_not_called()

    @patch.object(SolInteractor, 'get_token_account_balance_list')
    def test_deprive_permissions_positive_difference(self, mock_get_token_account_balance_list):
        """
        Should mint denial token - positive difference
        """
        allowance_balance = 143
        denial_balance = 103
        diff = allowance_balance - denial_balance
        min_balance = 3
        expected_mint = diff - min_balance + 1
        ether_address = 'Ethereum-Address'
        mint_authority_file = "/spl/bin/evm_loader-keypair.json"

        mock_get_token_account_balance_list.side_effect = [[allowance_balance, denial_balance]]

        self.assertTrue(self.testee.deprive_permissions(ether_address, min_balance, self.payer))

        self.testee.allowance_token.get_token_account_address.assert_called_once_with(ether_address)
        self.testee.denial_token.get_token_account_address.assert_called_once_with(ether_address)
        self.testee.denial_token.mint_to.assert_called_once_with(
            expected_mint, ether_address, mint_authority_file, self.payer
        )

    @patch.object(SolInteractor, 'get_token_account_balance_list')
    def test_deprive_permissions_negative_difference(self, mock_get_token_account_balance_list):
        """
        Should NOT mint denial token - negative difference
        """
        allowance_balance = 14
        denial_balance = 103
        min_balance = 3
        ether_address = 'Ethereum-Address'

        mock_get_token_account_balance_list.side_effect = [[allowance_balance, denial_balance]]

        self.assertTrue(self.testee.deprive_permissions(ether_address, min_balance, self.payer))

        self.testee.allowance_token.get_token_account_address.assert_called_once_with(ether_address)
        self.testee.denial_token.get_token_account_address.assert_called_once_with(ether_address)
        self.testee.denial_token.mint_to.assert_not_called()

    @patch.object(AccountWhitelist, 'get_current_time')
    @patch.object(SolInteractor, 'get_token_account_balance_list')
    def test_check_has_permission(self, mock_get_token_account_balance_list, mock_get_current_time):
        ether_address = 'Ethereum-Address'
        time1 = 123                                                    # will cause get_token_account_address call
        time2 = time1 + self.config.account_permission_update_int + 2  # will cause get_token_account_address call
        time3 = time2 + self.config.account_permission_update_int - 3  # will NOT cause get_token_account_address call
        mock_get_current_time.side_effect = [ time1, time2, time3 ]
        mock_get_token_account_balance_list.side_effect = [[100, 50], [100, 150]]

        self.assertTrue(self.testee.has_permission(ether_address, 0))
        self.assertFalse(self.testee.has_permission(ether_address, 0))
        self.assertFalse(self.testee.has_permission(ether_address, 0))

        mock_get_current_time.assert_has_calls([call()] * 3)
        self.testee.allowance_token.get_token_account_address.assert_has_calls([call(ether_address)] * 2)
        self.testee.denial_token.get_token_account_address.assert_has_calls([call(ether_address)] * 2)
