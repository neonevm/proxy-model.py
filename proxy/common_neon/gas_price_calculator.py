from decimal import Decimal
import math

from logged_groups import logged_group
from typing import Optional

from ..indexer.pythnetwork import PythNetworkClient

from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.config import Config


@logged_group("neon.gas_price_calculator")
class GasPriceCalculator:
    _sol_price_symbol = 'Crypto.SOL/USD'

    def __init__(self, config: Config, solana: SolInteractor) -> None:
        self._config = config
        self._pyth_network_client = PythNetworkClient(solana)
        self._sol_price_usd: Optional[Decimal] = None
        self._neon_price_usd = config.neon_price_usd
        self._min_gas_price: Optional[int] = None
        self._suggested_gas_price: Optional[int] = None

    def is_valid(self) -> bool:
        return (self._min_gas_price is not None) and (self._suggested_gas_price is not None)

    def has_price(self) -> bool:
        return self._pyth_network_client.has_price(self._sol_price_symbol)

    def update_mapping(self) -> bool:
        if self._config.pyth_mapping_account is None:
            return False
        self._pyth_network_client.update_mapping(self._config.pyth_mapping_account)
        return self.has_price()

    @property
    def min_gas_price(self) -> int:
        assert self.is_valid(), 'Failed to estimate gas price. Try again later'
        return self._min_gas_price

    @property
    def suggested_gas_price(self) -> int:
        assert self.is_valid(), 'Failed to estimate gas price. Try again later'
        return self._suggested_gas_price

    def update_gas_price(self) -> bool:
        min_gas_price = self._config.min_gas_price
        gas_price = self._get_gas_price_from_network()
        if gas_price is None:
            if (min_gas_price is not None) and (not self.is_valid()):
                self._suggested_gas_price = min_gas_price
                self._min_gas_price = min_gas_price
            return False

        self._suggested_gas_price = math.ceil(gas_price * (1 + self.gas_price_suggested_pct))
        self._min_gas_price = math.ceil(gas_price * (1 + self.operator_fee))

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

            return (self._sol_price_usd / self._neon_price_usd) * pow(Decimal(10), 9)
        except BaseException as exc:
            self.error('Failed to retrieve SOL price.', exc_info=exc)
            return None

    @property
    def operator_fee(self) -> Decimal:
        return self._config.operator_fee

    @property
    def gas_price_suggested_pct(self) -> Decimal:
        return self._config.operator_fee + self._config.gas_price_suggested_pct

    @property
    def sol_price_usd(self) -> Decimal:
        assert self.is_valid(), 'Failed to get SOL price. Try again later.'
        return self._sol_price_usd if self._sol_price_usd is not None else Decimal(0)

    @property
    def neon_price_usd(self) -> Decimal:
        return self._neon_price_usd
