from __future__ import annotations

from typing import List, Dict, Any, Optional

import dataclasses
import logging

from .solana_block import SolBlockInfo
from .utils import str_fmt_object, cached_method
from .evm_log_decoder import NeonLogTxEvent


LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class NeonTxResultInfo:
    block_slot: Optional[int] = None
    block_hash: Optional[str] = None
    tx_idx: Optional[int] = None

    sol_sig: Optional[str] = None
    sol_ix_idx: Optional[int] = None
    sol_ix_inner_idx: Optional[int] = None

    neon_sig: str = ''
    status: int = 0

    gas_used: int = 0
    sum_gas_used: int = 0

    log_list: List[Dict[str, Any]] = None

    is_completed = False
    is_canceled = False

    @staticmethod
    def from_dict(src: Dict[str, Any]) -> NeonTxResultInfo:
        return NeonTxResultInfo(**src)

    def __post_init__(self):
        if self.log_list is None:
            object.__setattr__(self, 'log_list', [])

    @cached_method
    def __str__(self) -> str:
        return str_fmt_object(self)

    def _reset_str(self) -> None:
        self.__str__.reset_cache(self)

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def add_event(self, event: NeonLogTxEvent) -> None:
        if self.block_slot is not None:
            LOG.warning(f'Neon tx {self.neon_sig} has completed event logs')
            return

        rec = {
            'address': '0x' + event.address.hex() if len(event.address) > 0 else '',
            'topics': ['0x' + topic.hex() for topic in event.topic_list],
            'data': '0x' + event.data.hex() if len(event.data) > 0 else '',

            'neonSolHash': event.sol_sig,
            'neonIxIdx': event.idx,
            'neonInnerIxIdx': event.inner_idx,
            'neonEventType': int(event.event_type),
            'neonEventLevel': event.event_level,
            'neonEventOrder': event.event_order,
            'neonIsHidden': event.is_hidden,
            'neonIsReverted': event.is_reverted,

            # 'transactionLogIndex': hex(tx_log_idx), # set when transaction is found
            # 'logIndex': hex(log_idx), # set when transaction is found
            # 'transactionIndex': hex(ix.idx), # set when transaction is found
            # 'blockNumber': block_number, # set when transaction is found
            # 'blockHash': block_hash # set when transaction is found
            # 'cumulativeGasUsed': sum_gas_used  # set when transaction is found
        }

        self.log_list.append(rec)
        self._reset_str()

    def set_res(self, status: int, gas_used: int) -> None:
        object.__setattr__(self, 'status', status)
        object.__setattr__(self, 'gas_used', gas_used)
        object.__setattr__(self, 'is_completed', True)
        self._reset_str()

    def set_canceled_res(self, gas_used: int) -> None:
        self.set_res(status=0, gas_used=gas_used)
        object.__setattr__(self, 'is_canceled', True)

    def set_lost_res(self, gas_used=1) -> None:
        self.set_res(status=0, gas_used=gas_used)
        object.__setattr__(self, 'is_completed', False)

    def set_sol_sig_info(self, sol_sig: str, sol_ix_idx: int, sol_ix_inner_idx: Optional[int]) -> None:
        object.__setattr__(self, 'sol_sig', sol_sig)
        object.__setattr__(self, 'sol_ix_idx', sol_ix_idx)
        object.__setattr__(self, 'sol_ix_inner_idx', sol_ix_inner_idx)
        self._reset_str()

    def set_block_info(self, block: SolBlockInfo, neon_sig: str, tx_idx: int, log_idx: int, sum_gas_used: int) -> int:
        object.__setattr__(self, 'block_slot', block.block_slot)
        object.__setattr__(self, 'block_hash', block.block_hash)
        object.__setattr__(self, 'neon_sig', neon_sig)
        object.__setattr__(self, 'tx_idx', tx_idx)
        object.__setattr__(self, 'sum_gas_used', sum_gas_used)
        self._reset_str()

        hex_block_slot = hex(self.block_slot)
        hex_tx_idx = hex(self.tx_idx)
        tx_log_idx = 0

        for rec in self.log_list:
            rec['transactionHash'] = neon_sig
            rec['blockHash'] = block.block_hash
            rec['blockNumber'] = hex_block_slot
            rec['transactionIndex'] = hex_tx_idx
            if not rec['neonIsHidden']:
                rec['logIndex'] = hex(log_idx)
                rec['transactionLogIndex'] = hex(tx_log_idx)
                log_idx += 1
                tx_log_idx += 1

        return log_idx

    def is_valid(self) -> bool:
        return self.is_completed
