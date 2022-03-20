from datetime import datetime
from decimal import Decimal
import time
import math
from logged_groups import logged_group
from ..indexer.pythnetwork import PythNetworkClient
from ..common_neon.solana_interactor import SolanaInteractor
from ..environment import MINIMAL_GAS_PRICE, OPERATOR_FEE, NEON_PRICE_USD, GAS_PRICE_SUGGESTED_PCT
from ..environment import SOL_PRICE_UPDATE_INTERVAL, GET_SOL_PRICE_MAX_RETRIES, GET_SOL_PRICE_RETRY_INTERVAL


@logged_group("neon.gas_price_calculator")
class GasPriceCalculator:
    def __init__(self, solana: SolanaInteractor, pyth_mapping_acc) -> None:
        self.solana = solana
        self.mapping_account = pyth_mapping_acc
        self.pyth_network_client = PythNetworkClient(self.solana)
        self.recent_sol_price_update_time = None
        self.min_gas_price = None
        self.sol_price_usd = None

    def env_min_gas_price(self):
        if MINIMAL_GAS_PRICE is not None:
            return MINIMAL_GAS_PRICE

    def update_mapping(self):
        if self.mapping_account is not None:
            self.pyth_network_client.update_mapping(self.mapping_account)

    def get_min_gas_price(self):
        if self.env_min_gas_price() is not None:
            return self.env_min_gas_price()
        self.try_update_gas_price()
        return self.min_gas_price

    def get_suggested_gas_price(self):
        return math.ceil(self.get_min_gas_price() * (1 + GAS_PRICE_SUGGESTED_PCT))

    def try_update_gas_price(self):
        cur_time = self.get_current_time()
        if self.recent_sol_price_update_time is None:
            self.start_update_gas_price(cur_time)
            return

        time_left = cur_time - self.recent_sol_price_update_time
        if time_left > SOL_PRICE_UPDATE_INTERVAL:
            self.start_update_gas_price(cur_time)

    def get_current_time(self):
        return datetime.now().timestamp()

    def start_update_gas_price(self, cur_time):
        num_retries = GET_SOL_PRICE_MAX_RETRIES

        while True:
            try:
                price = self.pyth_network_client.get_price('Crypto.SOL/USD')
                if price['status'] != 1: # tradable
                    raise Exception('Price status is not tradable')

                self.sol_price_usd = price['price']
                self.recent_sol_price_update_time = cur_time
                self.min_gas_price = (self.sol_price_usd / NEON_PRICE_USD) * (1 + OPERATOR_FEE) * pow(Decimal(10), 9)
                return

            except Exception as err:
                self.error(f'Failed to retrieve SOL price: {err}')
                num_retries -= 1
                if num_retries == 0:
                    # This error should be forwarded to client
                    raise Exception('Failed to estimate gas price. Try again later')

                self.info(f'Will retry getting price after {GET_SOL_PRICE_RETRY_INTERVAL} seconds')
                time.sleep(GET_SOL_PRICE_RETRY_INTERVAL)

    def get_sol_price_usd(self) -> float:
        if self.sol_price_usd:
            return float(self.sol_price_usd)
        return 0.0

    def get_neon_price_usd(self) -> float:
        return float(NEON_PRICE_USD)

    def get_operator_fee(self) -> float:
        return float(OPERATOR_FEE)
