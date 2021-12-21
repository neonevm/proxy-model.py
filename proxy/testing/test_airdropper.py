import unittest
from proxy.testing.mock_server import MockServer
from proxy.indexer.airdropper import Airdropper, AIRDROP_AMOUNT_SOL, NEON_PRICE_USD
from proxy.indexer.sql_dict import SQLDict
from proxy.indexer.price_provider import PriceProvider
import time
from flask import request, Response
from unittest.mock import Mock, MagicMock, patch, call, ANY
from decimal import Decimal
import itertools
from proxy.testing.transactions import pre_token_airdrop_trx1, pre_token_airdrop_trx2,\
    create_sol_acc_and_airdrop_trx, wrapper_whitelist, evm_loader_addr, token_airdrop_address1, \
    token_airdrop_address2, token_airdrop_address3

class MockFaucet(MockServer):
    def __init__(self, port):
        super().__init__(port)
        self.request_neon_in_galans_mock = MagicMock()
        self.request_neon_in_galans_mock.side_effect = itertools.repeat({})
        self.add_url_rule("/request_neon_in_galans", callback=self.request_neon_in_galans, methods=['POST'])

    def request_neon_in_galans(self):
        req = request.get_json()
        return self.request_neon_in_galans_mock(req)


def create_signature_for_address(signature: str):
    return {
        'blockTime': 1638177745, # not make sense
        'confirmationStatus': 'finalized',
        'err': None,
        'memo': None,
        'signature': signature,
        'slot': 9748200 # not make sense
    }


def create_get_signatures_for_address(signatures: list):
    return {
        'jsonrpc': '2.0',
        'result': [ create_signature_for_address(sign) for sign in signatures ],
        'id': 1
    }

def create_price_info(valid_slot: int, price: Decimal, conf: Decimal):
    return {
        'valid_slot':   valid_slot,
        'price':        price,
        'conf':         conf
    }


class Test_Airdropper(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        print("testing indexer in airdropper mode")
        cls.address = 'localhost'
        cls.faucet_port = 3333
        cls.evm_loader_id = evm_loader_addr
        cls.wrapper_whitelist = wrapper_whitelist
        cls.neon_decimals = 9
        cls.airdropper = Airdropper(f'http://{cls.address}:8899',
                                    cls.evm_loader_id,
                                    f'http://{cls.address}:{cls.faucet_port}',
                                    cls.wrapper_whitelist,
                                    'INFO',
                                    cls.neon_decimals)

        cls.mock_airdrop_ready = Mock()
        cls.mock_airdrop_ready.__setitem__ = MagicMock()
        cls.mock_airdrop_ready.__contains__ = MagicMock()
        cls.airdropper.airdrop_ready = cls.mock_airdrop_ready


    def setUp(self) -> None:
        print(f"\n\n{self._testMethodName}\n{self._testMethodDoc}")
        self.faucet = MockFaucet(self.faucet_port)
        self.faucet.start()
        time.sleep(0.2)


    def tearDown(self) -> None:
        self.faucet.shutdown_server()
        self.faucet.join()
        self.airdropper.airdrop_scheduled.clear()
        self.mock_airdrop_ready.__contains__.reset_mock()
        self.mock_airdrop_ready.__setitem__.reset_mock()

    @patch.object(PriceProvider, 'get_price')
    def test_failed_process_trx_with_one_airdrop_price_provider_error(self, mock_get_price):
        """
        Should not airdrop to new address due to price provider error
        """

        mock_get_price.side_effect = [None]
        self.mock_airdrop_ready.__contains__.side_effect = [False] # new eth address
        self.faucet.request_neon_in_galans_mock.side_effect = [Response("{}", status=200, mimetype='application/json')]

        self.airdropper._process_trx_airdropper_mode(pre_token_airdrop_trx1)
        self.airdropper._process_scheduled_trxs()

        self.mock_airdrop_ready.__contains__.assert_called_once_with(token_airdrop_address1)
        self.mock_airdrop_ready.__setitem__.assert_not_called()
        mock_get_price.assert_called_once_with('SOL/USD')
        self.faucet.request_neon_in_galans_mock.assert_not_called()

    @patch.object(PriceProvider, 'get_price')
    @patch.object(Airdropper, '_is_allowed_wrapper_contract')
    def test_failed_airdrop_contract_not_in_whitelist(self, mock_is_allowed_contract, mock_get_price):
        """
        Should not airdrop for contract that is not in whitelist
        """
        self.airdropper.current_slot = 1234
        mock_get_price.side_effect = [create_price_info(self.airdropper.current_slot,
                                                        Decimal('235.0'),
                                                        Decimal('1.3'))]
        mock_is_allowed_contract.side_effect = [False]
        self.airdropper._process_trx_airdropper_mode(pre_token_airdrop_trx1)
        self.airdropper._process_scheduled_trxs()

        mock_is_allowed_contract.assert_called_once()
        mock_get_price.assert_called_once_with('SOL/USD')
        self.mock_airdrop_ready.__contains__.assert_not_called()
        self.mock_airdrop_ready.__setitem__.assert_not_called()
        self.faucet.request_neon_in_galans_mock.assert_not_called()
    
    @patch.object(PriceProvider, 'get_price')
    def test_faucet_failure(self, mock_get_price):
        """
        Should not add address to processed list due to faucet error
        """
        sol_price = Decimal('341.5')
        airdrop_amount = int(pow(Decimal(10), self.neon_decimals) * (AIRDROP_AMOUNT_SOL * sol_price) / NEON_PRICE_USD)
        self.airdropper.current_slot = 1234
        mock_get_price.side_effect = [create_price_info(self.airdropper.current_slot,
                                                        sol_price,
                                                        Decimal('1.3'))]
        self.mock_airdrop_ready.__contains__.side_effect = [False]  # new eth address
        self.faucet.request_neon_in_galans_mock.side_effect = [Response("{}", status=400, mimetype='application/json')]

        self.airdropper._process_trx_airdropper_mode(pre_token_airdrop_trx1)
        self.airdropper._process_scheduled_trxs()

        self.mock_airdrop_ready.__contains__.assert_called_once_with(token_airdrop_address1)
        mock_get_price.assert_called_once_with('SOL/USD')
        self.mock_airdrop_ready.__setitem__.assert_not_called()
        json_req = {'wallet': token_airdrop_address1, 'amount': airdrop_amount}
        self.faucet.request_neon_in_galans_mock.assert_called_once_with(json_req)
    
    def test_process_trx_with_one_airdrop_for_already_processed_address(self):
        """
        Should not airdrop to repeated address
        """
        self.mock_airdrop_ready.__contains__.side_effect = [True]  # eth address processed earlier

        self.airdropper._process_trx_airdropper_mode(pre_token_airdrop_trx1)
        self.airdropper._process_scheduled_trxs()

        self.mock_airdrop_ready.__contains__.assert_called_once_with(token_airdrop_address1)
        self.mock_airdrop_ready.__setitem__.assert_not_called()
        self.faucet.request_neon_in_galans_mock.assert_not_called()
    
    @patch.object(PriceProvider, 'get_price')
    def test_failed_airdrop_confidence_interval_too_large(self, mock_get_price):
        """
        Should not airdrop because confidence interval too large
        """
        self.airdropper.current_slot = 1234
        mock_get_price.side_effect = [create_price_info(self.airdropper.current_slot,
                                                        Decimal('235.0'),
                                                        Decimal('54.0'))] # << BIG CONFIDENCE INTERVAL
        self.airdropper._process_trx_airdropper_mode(pre_token_airdrop_trx1)
        self.airdropper._process_scheduled_trxs()

        mock_get_price.assert_called_once_with('SOL/USD')
        self.mock_airdrop_ready.__contains__.assert_called_once_with(token_airdrop_address1)
        self.mock_airdrop_ready.__setitem__.assert_not_called()
        self.faucet.request_neon_in_galans_mock.assert_not_called()
