from dataclasses import dataclass, field
from typing import List


class NeonTxStatData:
    def __init__(self, neon_tx_hash: str, neon_income: int, tx_type: str, is_canceled: bool) -> None:
        self.neon_tx_hash = neon_tx_hash
        self.neon_income = neon_income
        self.tx_type = tx_type
        self.is_canceled = is_canceled
        self.instructions = []

    def add_instruction(self, sol_tx_hash: str, sol_spent: int, steps: int, bpf: int) -> None:
        self.instructions.append((sol_tx_hash, sol_spent, steps, bpf))


@dataclass
class NeonTxReturn:
    exit_status: int = 0
    gas_used: int = 0
    return_value: bytes = b''


@dataclass
class NeonEvent:
    address: bytes = b''
    count_topics: int = 0
    topics: List[bytes] = field(default_factory=list)
    log_data: bytes = b''


@dataclass
class NeonLogIx:
    neon_return: NeonTxReturn = field(default_factory=NeonTxReturn)
    neon_events: List[NeonEvent] = field(default_factory=list)
