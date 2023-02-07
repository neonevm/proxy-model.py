from dataclasses import dataclass
from decimal import Decimal
from typing import List


@dataclass(frozen=True)
class NeonMethodData:
    name: str
    is_error: bool
    latency: float


class NeonTxStatData:
    tx_type: str
    completed_neon_tx_cnt: int = 0
    canceled_neon_tx_cnt: int = 0
    sol_tx_cnt: int = 0
    sol_spent: int = 0
    neon_income: int = 0
    neon_step_cnt: int = 0
    bpf_cycle_cnt: int = 0

    op_sol_spent: int = 0
    op_neon_income: int = 0
    op_completed_neon_tx_cnt: int = 0
    op_canceled_neon_tx_cnt: int = 0


@dataclass(frozen=True)
class NeonGasPriceData:
    min_gas_price: int
    sol_price_usd: Decimal
    neon_price_usd: Decimal
    operator_fee: Decimal


@dataclass(frozen=True)
class NeonTxBeginData:
    begin_cnt: int


@dataclass(frozen=True)
class NeonTxEndData:
    done_cnt: int
    failed_cnt: int
    rescheduled_cnt: int


@dataclass(frozen=True)
class NeonOpResListData:
    sol_account_list: List[str]
    neon_account_list: List[str]


@dataclass(frozen=True)
class NeonOpResStatData:
    secret_cnt: int
    total_res_cnt: int
    free_res_cnt: int
    used_res_cnt: int
    disabled_res_cnt: int


@dataclass(frozen=True)
class NeonExecutorStatData:
    total_cnt: int
    free_cnt: int
    used_cnt: int
    stopped_cnt: int


@dataclass(frozen=True)
class NeonBlockStatData:
    start_block: int
    parsed_block: int
    finalized_block: int
    confirmed_block: int
