from proxy.indexer.price_provider import PriceProvider, field_info, PRICE_STATUS_TRADING, PRICE_STATUS_UNKNOWN, price_accounts
from unittest import TestCase
from unittest.mock import patch, MagicMock, call
from datetime import datetime
from solana.rpc.api import Client
from solana.publickey import PublicKey
from struct import pack
from random import uniform


class TestPriceProvider(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        print("Testing PriceProvider")
        cls.solana_url = 'https://api.mainnet-beta.solana.com' # use contract in mainnet
        cls.default_upd_int = 10


    def setUp(self) -> None:
        self.price_provider = PriceProvider(self.solana_url,
                                            self.default_upd_int)

    def _create_price_account_info(self, price: float, status: int):
        # Follow link https://github.com/pyth-network/pyth-client-rs/blob/main/src/lib.rs
        # for details on structure of pyth.network price accounts.
        # Current implementation of PriceProvider uses only few fields of account
        # so no need to generate all data in tests

        exponent = -8 # use as default
        # Fill gap between account data begining and expo field with zeros
        data = b'\x00' * field_info['expo']['pos']
        data += pack(field_info['expo']['format'], exponent)

        raw_price = int(price / pow(10, exponent))
        # fill gap between expo and agg.price fields with zeros
        data += b'\x00' * (field_info['agg.price']['pos'] - len(data))
        data += pack(field_info['agg.price']['format'], raw_price)

        # fill gap between agg.price and agg.status fields with zeros
        data += b'\x00' * (field_info['agg.status']['pos'] - len(data))
        data += pack(field_info['agg.status']['format'], status)
        # rest of data array is not used by PriceProvier so no need to fill it

        return {
            'result': {
                'value': {
                    'data': [
                        data,
                        'base64'
                    ]
                }
            }
        }

    @patch.object(Client, 'get_account_info')
    @patch.object(datetime, 'now')
    def test_success_read_price_two_times_with_small_interval(self, mock_now, mock_get_account_info):
        print("Should call get_price two times but will cause only one call to get_account_info")
        mock_nowtime = MagicMock()
        mock_timestamp = MagicMock()
        mock_nowtime.timestamp = mock_timestamp

        # some random time
        first_call_time =  uniform(0, 100000)
        # not enough time left to cause second account reload
        second_call_time = first_call_time + self.default_upd_int - 1

        mock_now.side_effect = [mock_nowtime, mock_nowtime]
        mock_timestamp.side_effect = [ first_call_time, second_call_time]

        current_price = 315.0
        mock_get_account_info.side_effect = [self._create_price_account_info(current_price, PRICE_STATUS_TRADING)]

        pair_name = 'SOL/USD'
        self.assertEqual(self.price_provider.get_price(pair_name), current_price)
        self.assertEqual(self.price_provider.get_price(pair_name), current_price)

        mock_now.assert_has_calls([call(),call()])
        mock_timestamp.assert_has_calls([call(), call()])
        mock_get_account_info.assert_called_once_with(PublicKey(price_accounts[pair_name]))
