from dataclasses import dataclass
from decimal import Decimal
from typing import List
from enum import Enum, auto as enum_auto


@dataclass(frozen=True)
class NeonMethodData:
    name: str
    is_error: bool
    latency: float


@dataclass
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


class NeonTxBeginCode(Enum):
    Failed = enum_auto()
    Started = enum_auto()
    Restarted = enum_auto()
    StuckPushed = enum_auto()


@dataclass
class NeonTxBeginData:
    started_cnt: int = 0
    restarted_cnt: int = 0
    stuck_pushed_cnt: int = 0
    total_cnt: int = 0

    def add_value(self, code: NeonTxBeginCode) -> None:
        if code == NeonTxBeginCode.Started:
            self.started_cnt += 1
        elif code == NeonTxBeginCode.Restarted:
            self.restarted_cnt += 1
        elif code == NeonTxBeginCode.StuckPushed:
            self.stuck_pushed_cnt += 1
        else:
            return
        self.total_cnt += 1

    def has_value(self) -> bool:
        return self.total_cnt > 0


class NeonTxEndCode(Enum):
    Unspecified = enum_auto()
    Unfinished = enum_auto()
    Done = enum_auto()
    StuckDone = enum_auto()
    Failed = enum_auto()
    Rescheduled = enum_auto()
    Canceled = enum_auto()


@dataclass
class NeonTxEndData:
    done_cnt: int = 0
    stuck_done_cnt: int = 0
    failed_cnt: int = 0
    rescheduled_cnt: int = 0
    canceled_cnt: int = 0
    total_cnt: int = 0

    def add_value(self, code: NeonTxEndCode) -> None:
        if code == NeonTxEndCode.Done:
            self.done_cnt += 1
        elif code == NeonTxEndCode.Failed:
            self.failed_cnt += 1
        elif code == NeonTxEndCode.Rescheduled:
            self.rescheduled_cnt += 1
        elif code == NeonTxEndCode.Canceled:
            self.canceled_cnt += 1
        elif code == NeonTxEndCode.StuckDone:
            self.stuck_done_cnt += 1
        else:
            return
        self.total_cnt += 1

    def has_value(self) -> bool:
        return self.total_cnt > 0


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
