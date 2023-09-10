import logging
import math

from decimal import Decimal
from typing import Optional

from .pythnetwork import PythNetworkClient
from ..common_neon.config import Config
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx import SolPubKey
from ..common_neon.errors import PythNetworkError


LOG = logging.getLogger(__name__)


class GasPriceCalculator:
    _sol_price_symbol = 'Crypto.SOL/USD'
    _neon_price_symbol = 'Crypto.NEON/USD'

    def __init__(self, config: Config, solana: SolInteractor) -> None:
        self._config = config
        self._pyth_network_client = PythNetworkClient(solana)
        self._sol_price_usd: Optional[Decimal] = None
        self._neon_price_usd: Optional[Decimal] = None
        self._is_const_gas_price = True
        self._min_gas_price: Optional[int] = None
        self._suggested_gas_price: Optional[int] = None

    def set_price_account(self, sol_price_account: Optional[SolPubKey], neon_price_account: Optional[SolPubKey]):
        if (sol_price_account is None) or (neon_price_account is None):
            return

        self._pyth_network_client.set_price_account(self._sol_price_symbol, sol_price_account)
        self._pyth_network_client.set_price_account(self._neon_price_symbol, neon_price_account)

    def is_valid(self) -> bool:
        return (self._min_gas_price is not None) and (self._suggested_gas_price is not None)

    def has_price(self) -> bool:
        return (
            self._pyth_network_client.has_price(self._sol_price_symbol) and
            self._pyth_network_client.has_price(self._neon_price_symbol)
        )

    def update_mapping(self) -> bool:
        try:
            if self._config.pyth_mapping_account is None:
                return False

            self._pyth_network_client.update_mapping(self._config.pyth_mapping_account)
            return self.has_price()
        except BaseException as exc:
            LOG.debug('Failed to update pyth.network mapping', exc_info=exc)
            return False

    def update_gas_price(self) -> bool:
        self._get_tokens_prices_from_net()
        cfg_const_gas_price = self._config.const_gas_price

        if cfg_const_gas_price is not None:
            self._is_const_gas_price = True
            self._suggested_gas_price = cfg_const_gas_price
            self._min_gas_price = cfg_const_gas_price
            return False

        cfg_min_gas_price = self._config.min_gas_price

        if self._config.pyth_mapping_account is None:
            self._is_const_gas_price = True
            self._suggested_gas_price = cfg_min_gas_price
            self._min_gas_price = cfg_min_gas_price
            return False

        self._is_const_gas_price = False

        net_gas_price = self._calc_gas_price_from_net()
        if net_gas_price is None:
            self._suggested_gas_price = None
            self._min_gas_price = None
            return True

        suggested_gas_price = math.ceil(net_gas_price * (1 + self.gas_price_suggested_pct))
        min_gas_price = math.ceil(net_gas_price * (1 + self.operator_fee))

        self._suggested_gas_price = max(suggested_gas_price, cfg_min_gas_price)
        self._min_gas_price = max(min_gas_price, cfg_min_gas_price)

        return True

    def _get_tokens_prices_from_net(self) -> None:
        if self._config.pyth_mapping_account is None:
            return

        try:
            self._neon_price_usd = self._get_token_price(self._neon_price_symbol)
        except PythNetworkError as exc:
            LOG.debug(f'Failed to retrieve NEON price: {str(exc)}')
        except BaseException as exc:
            LOG.error('Failed to retrieve NEON price', exc_info=exc)

        try:
            self._sol_price_usd = self._get_token_price(self._sol_price_symbol)
        except PythNetworkError as exc:
            LOG.debug(f'Failed to retrieve SOL price: {str(exc)}')
        except BaseException as exc:
            LOG.error('Failed to retrieve SOL price', exc_info=exc)

    def _calc_gas_price_from_net(self) -> Optional[int]:
        if (self._sol_price_usd is None) or (self._neon_price_usd is None):
            return None

        return round((self._sol_price_usd / self._neon_price_usd) * pow(Decimal(10), 9))

    def _get_token_price(self, symbol: str) -> Decimal:
        price = self._pyth_network_client.get_price(symbol)
        if price is None:
            raise RuntimeError(f'{symbol} price is absent in the pyth.network list')
        if price.get('status', 0) != 1:  # tradable
            raise PythNetworkError(f'{symbol} price status is not tradable')
        return Decimal(price['price'])

    @property
    def operator_fee(self) -> Decimal:
        return self._config.operator_fee

    @property
    def gas_price_slippage(self) -> Decimal:
        return self._config.gas_price_slippage

    @property
    def is_const_gas_price(self) -> bool:
        return self._is_const_gas_price

    @property
    def gas_price_suggested_pct(self) -> Decimal:
        return self.operator_fee + self.gas_price_slippage

    @property
    def min_gas_price(self) -> int:
        assert self.is_valid(), 'Failed to calculate gas price. Try again later'
        return self._min_gas_price

    @property
    def suggested_gas_price(self) -> int:
        assert self.is_valid(), 'Failed to calculate gas price. Try again later'
        return self._suggested_gas_price

    @property
    def sol_price_account(self) -> Optional[SolPubKey]:
        return self._pyth_network_client.get_price_account(self._sol_price_symbol)

    @property
    def neon_price_account(self) -> Optional[SolPubKey]:
        return self._pyth_network_client.get_price_account(self._neon_price_symbol)

    @property
    def sol_price_usd(self) -> Decimal:
        return self._sol_price_usd if self._sol_price_usd is not None else Decimal(0)

    @property
    def neon_price_usd(self) -> Decimal:
        return self._neon_price_usd if self._neon_price_usd is not None else Decimal(0)
