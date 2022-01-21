from datetime import datetime
import time
from logged_groups import logged_group
from ..indexer.pythnetwork import PythNetworkClient
from ..environment import MINIMAL_GAS_PRICE

SOL_PRICE_UPDATE_INTERVAL = 60
GET_PRICE_MAX_RETRIES = 3
GET_PRICE_RETRY_INTERVAL = 1

@logged_group("neon.gas_price_calculator")
class GasPriceCalculator:
    def __init__(self, solana_client) -> None:
        self.solana_client = solana_client
        self.pyth_network_client = PythNetworkClient(self.client)
        self.recent_sol_price = None
        self.recent_sol_price_update_time = None

    def get_min_gas_price(self):
        if MINIMAL_GAS_PRICE is not None:
            return hex(MINIMAL_GAS_PRICE)
        return self.calculate_gas_price()

    def calculate_gas_price(self):
        return MINIMAL_GAS_PRICE

    def get_sol_price(self):
        cur_time = datetime.now().timestamp()
        if self.recent_sol_price_update_time is not None:
            time_left = cur_time - self.recent_sol_price_update_time
            if time_left > SOL_PRICE_UPDATE_INTERVAL:
                num_retries = GET_PRICE_MAX_RETRIES

                while True:
                    try:
                        price = self.pyth_network_client.get_price()
                        if price['status'] != 1: # tradable
                            raise Exception('Price status is not tradable')

                        self.recent_sol_price = price['price']
                        self.recent_sol_price_update_time = cur_time
                        break

                    except Exception as err:
                        self.warning(f'Failed to retrieve SOL price: {err}')
                        num_retries -= 1
                        if num_retries == 0:
                            break

                        self.info(f'Will retry getting price after {GET_PRICE_RETRY_INTERVAL} seconds')
                        time.sleep(GET_PRICE_RETRY_INTERVAL)

        return self.recent_sol_price