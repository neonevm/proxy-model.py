import unittest
from unittest.mock import patch, call
from proxy.common_neon.pythnetwork import PythNetworkClient
from proxy.common_neon.solana_interactor import SolInteractor
from proxy.common_neon.config import Config
from proxy.common_neon.solana_tx import SolPubKey
from decimal import Decimal

# Will perform tests with devnet network
# CI Airdropper that is already running in parallel (see docker-compose-test.yml)
# uses mainnet-beta.
# PythNetworkClient will fail with 'too many requests' if trying to connect
# it to the same Solana network
solana_url = "https://api.devnet.solana.com"
mapping_account = SolPubKey('BmA9Z6FjioHJPpjT39QazZyhDRUdZy2ezwx4GiDdE2u2')
sol_usd_symbol = 'Crypto.SOL/USD'


class TestPythNetworkClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.price_acct1_addr = SolPubKey(b'PriceAcct1')
        cls.price_acct2_addr = SolPubKey(b'PriceAcct2')

        cls.prod_acct1_addr = SolPubKey(b'ProdAcct1')
        cls.prod_acct2_addr = SolPubKey(b'ProdAcct2')

        cls.prod_acct1_data = b'Acct1Data'
        cls.prod_acct2_data = b'Acct2Data'

        cls.prod1_symbol = 'PROD1/USD'
        cls.prod2_symbol = 'PROD2/USD'

        cls.prod_acct1 = {
            'price_acc': cls.price_acct1_addr,
            'attrs': {
                'symbol': cls.prod1_symbol
            }
        }
        cls.prod_acct2 = {
            'price_acc': cls.price_acct2_addr,
            'attrs': {
                'symbol': cls.prod2_symbol
            }
        }

        cls.prod1_price_data = {
            'valid_slot':   1234,
            'price':        Decimal(123),
            'conf':         Decimal(3) * Decimal(0.1),
            'status':       1
        }

        cls.prod2_price_data = {
            'valid_slot':   1234,
            'price':        Decimal(345),
            'conf':         Decimal(5) * Decimal(0.1),
            'status':       1
        }

        cls.testee = PythNetworkClient(SolInteractor(Config(), solana_url))

    def update_mapping(self):
        self.testee.update_mapping(mapping_account)

    @patch.object(PythNetworkClient, 'read_pyth_acct_data')
    @patch.object(PythNetworkClient, 'parse_mapping_account')
    @patch.object(PythNetworkClient, 'parse_prod_account')
    @patch.object(PythNetworkClient, 'parse_price_account')
    def test_success_update_mapping(self,
                                    mock_parse_price_account,
                                    mock_parse_prod_account,
                                    mock_parse_mapping_account,
                                    mock_read_pyth_acct_data):
        '''
        Should succesfully load all data
        '''
        mock_parse_mapping_account.side_effect = [[self.prod_acct1_addr, self.prod_acct2_addr]]
        mock_read_pyth_acct_data.side_effect = [{ str(self.prod_acct1_addr): self.prod_acct1_data,
                                                  str(self.prod_acct2_addr): self.prod_acct2_data }]
        mock_parse_prod_account.side_effect = [self.prod_acct1, self.prod_acct2]
        mock_parse_price_account.side_effect = [self.prod1_price_data, self.prod2_price_data]
        try:
            self.update_mapping()
            self.assertEqual(self.testee.get_price(self.prod1_symbol), self.prod1_price_data)
            self.assertEqual(self.testee.get_price(self.prod2_symbol), self.prod2_price_data)

            mock_parse_mapping_account.assert_called_once_with(mapping_account)
            mock_read_pyth_acct_data.assert_called_once_with([self.prod_acct1_addr, self.prod_acct2_addr])
            mock_parse_prod_account.assert_has_calls([call(self.prod_acct1_data), call(self.prod_acct2_data)])
            mock_parse_price_account.assert_has_calls([call(self.price_acct1_addr), call(self.price_acct2_addr)])
        except Exception as err:
            self.fail(f"Expected not throws exception but it does: {err}")

    @patch.object(PythNetworkClient, 'read_pyth_acct_data')
    @patch.object(PythNetworkClient, 'parse_mapping_account')
    @patch.object(PythNetworkClient, 'parse_prod_account')
    @patch.object(PythNetworkClient, 'parse_price_account')
    def test_continue_when_failed_prod_account(self,
                                               mock_parse_price_account,
                                               mock_parse_prod_account,
                                               mock_parse_mapping_account,
                                               mock_read_pyth_acct_data):
        '''
        Should continue reading product accounts when one of them failed to read
        '''
        mock_parse_mapping_account.side_effect = [[self.prod_acct1_addr, self.prod_acct2_addr]]
        mock_read_pyth_acct_data.side_effect = [{ str(self.prod_acct1_addr): None,
                                                  str(self.prod_acct2_addr): self.prod_acct2_data }]
        mock_parse_prod_account.side_effect = [self.prod_acct2]
        mock_parse_price_account.side_effect = [self.prod2_price_data]
        try:
            self.update_mapping()

            with self.assertRaises(Exception): # get_price for 1st product should fail
                self.assertEqual(self.testee.get_price(self.prod1_symbol), self.prod1_price_data)

            self.assertEqual(self.testee.get_price(self.prod2_symbol), self.prod2_price_data)

            mock_parse_mapping_account.assert_called_once_with(mapping_account)
            mock_read_pyth_acct_data.assert_called_once_with([self.prod_acct1_addr, self.prod_acct2_addr])
            mock_parse_prod_account.assert_called_once_with(self.prod_acct2_data)
            mock_parse_price_account.assert_has_calls([call(self.price_acct2_addr)])
        except Exception as err:
            self.fail(f"Expected not throws exception but it does: {err}")

    @patch.object(SolInteractor, 'get_account_info')
    def test_forward_exception_when_reading_mapping_account(self, mock_get_account_info):
        mock_get_account_info.side_effect = Exception('TestException')
        with self.assertRaises(Exception):
            self.update_mapping()
        mock_get_account_info.assert_called_once_with(mapping_account)

    def test_integration_success_read_price(self):
        '''
        Reading mapping account and prices from real Solana (This test might fail sometimes)
        '''
        try:
            self.update_mapping()
            self.testee.get_price(sol_usd_symbol)
        except Exception as err:
            self.fail(f"Expected get_price not throws exception but it does: {err}")
