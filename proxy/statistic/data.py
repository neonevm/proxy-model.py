from dataclasses import dataclass
from decimal import Decimal
from typing import List


@dataclass(frozen=True)
class NeonMethodData:
    name: str
    is_error: bool
    latency: float


@dataclass(frozen=True)
class NeonTxStatData:
    neon_tx_sig: str
    sol_spent: int
    neon_income: int
    tx_type: str
    is_canceled: bool
    neon_step_cnt: int
    bpf_cycle_cnt: int
    sol_tx_cnt: int


@dataclass(frozen=True)
class NeonGasPriceData:
    gas_price: int
    sol_price_usd: Decimal
    neon_price_usd: Decimal
    operator_fee: Decimal
    suggested_pct: Decimal


@dataclass(frozen=True)
class NeonOpListData:
    sol_account_list: List[str]
    neon_account_list: List[str]
