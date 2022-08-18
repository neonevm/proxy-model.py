from decimal import Decimal
import math

from logged_groups import logged_group
from typing import Optional

from solana.publickey import PublicKey

from ..indexer.pythnetwork import PythNetworkClient
from ..common_neon.solana_interactor import SolanaInteractor
from .environment_data import MINIMAL_GAS_PRICE, OPERATOR_FEE, GAS_PRICE_SUGGESTED_PCT, NEON_PRICE_USD


@logged_group("neon.gas_price_calculator")
class GasPriceCalculator:
    _sol_price_symbol = 'Crypto.SOL/USD'

    def __init__(self, solana: SolanaInteractor, pyth_mapping_acc: PublicKey) -> None:
        self._mapping_account = pyth_mapping_acc
        self._pyth_network_client = PythNetworkClient(solana)
        self._sol_price_usd: Optional[Decimal] = None
        self._min_gas_price: Optional[int] = None
        self._suggested_gas_price: Optional[int] = None

    @staticmethod
    def _get_env_min_gas_price() -> Optional[int]:
        if MINIMAL_GAS_PRICE is not None:
            return MINIMAL_GAS_PRICE
        return None

    def is_valid(self) -> bool:
        return (self._min_gas_price is not None) and (self._suggested_gas_price is not None)

    def has_price(self) -> bool:
        return self._pyth_network_client.has_price(self._sol_price_symbol)

    def update_mapping(self) -> bool:
        if self._mapping_account is None:
            return False
        self._pyth_network_client.update_mapping(self._mapping_account)
        return self.has_price()

    def get_min_gas_price(self) -> int:
        assert self.is_valid(), 'Failed to estimate gas price. Try again later'
        return self._min_gas_price

    def get_suggested_gas_price(self) -> int:
        assert self.is_valid(), 'Failed to estimate gas price. Try again later'
        return self._suggested_gas_price

    def update_gas_price(self) -> bool:
        min_gas_price = self._get_env_min_gas_price()
        gas_price = self._get_gas_price_from_network()
        if gas_price is None:
            if (min_gas_price is not None) and (not self.is_valid()):
                self._suggested_gas_price = min_gas_price
                self._min_gas_price = min_gas_price
            return False

        self._suggested_gas_price = math.ceil(gas_price * (1 + GAS_PRICE_SUGGESTED_PCT + self.get_operator_fee()))
        self._min_gas_price = math.ceil(gas_price * (1 + self.get_operator_fee()))

        if min_gas_price is not None:
            self._suggested_gas_price = max(self._suggested_gas_price, min_gas_price)
            self._min_gas_price = max(self._min_gas_price, min_gas_price)

        return True

    def _get_gas_price_from_network(self) -> Optional[int]:
        try:
            price = self._pyth_network_client.get_price(self._sol_price_symbol)
            if price.get('status', 0) != 1:  # tradable
                raise RuntimeError('Price status is not tradable')
            self._sol_price_usd = Decimal(price['price'])

            return (self._sol_price_usd / self.get_neon_price_usd()) * pow(Decimal(10), 9)
        except Exception as err:
            self.error(f'Failed to retrieve SOL price: {err}')
            return None

    def get_sol_price_usd(self) -> Decimal:
        assert self.is_valid(), 'Failed to get SOL price. Try again later.'
        return Decimal(0)

    @staticmethod
    def get_neon_price_usd() -> Decimal:
        return NEON_PRICE_USD

    @staticmethod
    def get_operator_fee() -> Decimal:
        assert (OPERATOR_FEE > 0) and (OPERATOR_FEE < 1)
        return OPERATOR_FEE
