import unittest

from typing import Optional

from ..indexer.pythnetwork import PythNetworkClient
from ..common_neon.solana_transaction import SolPubKey
from ..common_neon.gas_price_calculator import GasPriceCalculator
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.config import Config
from unittest.mock import patch, call
from decimal import Decimal


class FakeConfig(Config):
    @property
    def pyth_mapping_account(self) -> SolPubKey:
        return SolPubKey('BmA9Z6FjioHJPpjT39QazZyhDRUdZy2ezwx4GiDdE2u2')  # only for devnet

    @property
    def min_gas_price(self) -> Optional[int]:
        return None


class TestGasPriceCalculator(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        config = FakeConfig()
        solana_url = "https://api.devnet.solana.com"  # devnet
        solana = SolInteractor(config, solana_url)
        testee = GasPriceCalculator(config, solana)
        testee.update_mapping()
        cls.testee = testee
        cls.config = config

    def setUp(self) -> None:
        # reset time on test begins
        self.testee.recent_sol_price_update_time = None

    @patch.object(PythNetworkClient, 'get_price')
    def test_success_update_price(self, mock_get_price):
        """
        Should succesfully calculate gas price on first attempt
        """
        sol_price = Decimal('156.3')

        mock_get_price.side_effect = [{'status': 1, 'price': sol_price}]

        self.testee.update_gas_price()
        gas_price = self.testee.min_gas_price
        expected_price = (sol_price / self.testee.neon_price_usd) * (1 + self.testee.operator_fee) * pow(Decimal(10), 9)
        self.assertEqual(gas_price, expected_price)

        mock_get_price.assert_called_once_with('Crypto.SOL/USD')

    @patch.object(PythNetworkClient, 'get_price')
    def test_success_update_price_after_retry_due_to_wrong_price_status(self, mock_get_price):
        """
        Should retry get_price after wrong price status
        """
        sol_price = Decimal('156.3')

        mock_get_price.side_effect = [
            {'status': 0, 'price': sol_price},  # <--- Wrong price status
            {'status': 1, 'price': sol_price}
        ]

        for i in range(2):
            self.testee.update_gas_price()

        gas_price = self.testee.min_gas_price
        expected_price = (sol_price / self.testee.neon_price_usd) * (1 + self.testee.operator_fee) * pow(Decimal(10), 9)
        self.assertEqual(gas_price, expected_price)

        mock_get_price.assert_has_calls([call('Crypto.SOL/USD')] * 2)

    @patch.object(PythNetworkClient, 'get_price')
    def test_success_update_price_after_retry_due_to_get_price_exception(self, mock_get_price):
        """
        Should retry get_price after exception
        """
        sol_price = Decimal('156.3')

        mock_get_price.side_effect = [
            Exception("Test exception happened"),
            {'status': 1, 'price': sol_price}
        ]

        for i in range(2):
            self.testee.update_gas_price()

        gas_price = self.testee.min_gas_price
        expected_price = (sol_price / self.testee.neon_price_usd) * (1 + self.testee.operator_fee) * pow(Decimal(10), 9)
        self.assertEqual(gas_price, expected_price)

        mock_get_price.assert_has_calls([call('Crypto.SOL/USD')] * 2)
