from __future__ import annotations

from typing import Iterable, Dict, Any, Optional, Tuple

import dataclasses
import logging

from .solana_block import SolBlockInfo
from .utils.utils import str_fmt_object, cached_method, cached_property
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

    event_list: Tuple[NeonLogTxEvent, ...] = tuple()

    is_completed = False
    is_canceled = False

    @staticmethod
    def from_dict(src: Dict[str, Any]) -> NeonTxResultInfo:
        return NeonTxResultInfo(**src)

    @cached_method
    def __str__(self) -> str:
        return str_fmt_object(self)

    @cached_property
    def log_bloom(self) -> int:
        value = 0
        for event in self.event_list:
            value |= event.log_bloom
        return value

    def _reset_cache(self) -> None:
        self.__str__.reset_cache(self)
        if len(self.event_list) > 0:
            self.__dict__.pop('log_bloom', None)

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def add_event(self, event: NeonLogTxEvent) -> None:
        if self.block_slot is not None:
            LOG.warning(f'Neon tx {self.neon_sig} has completed event logs')
            return

        event_list = self.event_list + (event,)
        object.__setattr__(self, 'event_list', event_list)
        self._reset_cache()

    def set_event_list(self, event_list: Iterable[NeonLogTxEvent]) -> None:
        object.__setattr__(self, 'event_list', tuple(event_list))
        self._reset_cache()

    def set_res(self, status: int, gas_used: int) -> None:
        object.__setattr__(self, 'status', status)
        object.__setattr__(self, 'gas_used', gas_used)
        object.__setattr__(self, 'is_completed', True)
        self._reset_cache()

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
        self._reset_cache()

    def set_block_info(self, block: SolBlockInfo, neon_sig: str, tx_idx: int, log_idx: int, sum_gas_used: int) -> int:
        object.__setattr__(self, 'block_slot', block.block_slot)
        object.__setattr__(self, 'block_hash', block.block_hash)
        object.__setattr__(self, 'neon_sig', neon_sig)
        object.__setattr__(self, 'tx_idx', tx_idx)
        object.__setattr__(self, 'sum_gas_used', sum_gas_used)
        self._reset_cache()

        tx_log_idx = 0
        for event in self.event_list:
            event.set_tx_info(
                neon_sig=neon_sig,
                block_hash=block.block_hash,
                block_slot=block.block_slot,
                neon_tx_idx=tx_idx,
            )
            if not event.is_hidden:
                event.set_log_idx(block_log_idx=log_idx, neon_tx_log_idx=tx_log_idx)
                log_idx += 1
                tx_log_idx += 1

        return log_idx

    def is_valid(self) -> bool:
        return self.is_completed
