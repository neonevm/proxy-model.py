from typing import List, Dict, Any, Optional
from dataclasses import dataclass

import logging

from .solana_block import SolBlockInfo
from .utils import str_fmt_object
from ..evm_log_decoder import NeonLogTxEvent


LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class NeonTxResultInfo:
    block_slot: Optional[int] = None
    block_hash: Optional[str] = None
    tx_idx: Optional[int] = None

    sol_sig: Optional[str] = None
    sol_ix_idx: Optional[int] = None
    sol_ix_inner_idx: Optional[int] = None

    neon_sig: str = ''
    gas_used: str = ''
    status: str = ''

    log_list: List[Dict[str, Any]] = None

    canceled_status = 0
    lost_status = 0
    _str = ''

    def __post_init__(self):
        object.__setattr__(self, 'log_list', [])

    def __str__(self) -> str:
        if self._str == '':
            object.__setattr__(self, '_str', str_fmt_object(self))
        return self._str

    def add_event(self, event: NeonLogTxEvent) -> None:
        if self.block_slot is not None:
            LOG.warning(f'Neon tx {self.neon_sig} has completed event logs')
            return

        rec = {
            'address': '0x' + event.address.hex() if len(event.address) > 0 else '',
            'topics': ['0x' + topic.hex() for topic in event.topic_list],
            'data': '0x' + event.data.hex() if len(event.data) > 0 else '',

            'neonSolHash': event.sol_sig,
            'neonIxIdx': hex(event.idx),
            'neonInnerIxIdx': None if event.inner_idx is None else hex(event.inner_idx),
            'neonEventType': int(event.event_type),
            'neonEventLevel': hex(event.event_level),
            'neonEventOrder': hex(event.event_order),
            'neonIsHidden': event.is_hidden,
            'neonIsReverted': event.is_reverted,

            # 'transactionLogIndex': hex(tx_log_idx), # set when transaction found
            # 'logIndex': hex(log_idx), # set when transaction found
            # 'transactionIndex': hex(ix.idx), # set when transaction found
            # 'blockNumber': block_number, # set when transaction found
            # 'blockHash': block_hash # set when transaction found
        }

        self.log_list.append(rec)
        object.__setattr__(self, '_str', '')

    def set_result(self, status: int, gas_used: int) -> None:
        object.__setattr__(self, 'status', hex(status))
        object.__setattr__(self, 'gas_used', hex(gas_used))
        object.__setattr__(self, '_str', '')

    def set_canceled_result(self, gas_used: int) -> None:
        self.set_result(status=self.canceled_status, gas_used=gas_used)

    def set_lost_result(self, gas_used: int) -> None:
        self.set_result(status=self.lost_status, gas_used=gas_used)

    def set_sol_sig_info(self, sol_sig: str, sol_ix_idx: int, sol_ix_inner_idx: Optional[int]) -> None:
        object.__setattr__(self, 'sol_sig', sol_sig)
        object.__setattr__(self, 'sol_ix_idx', sol_ix_idx)
        object.__setattr__(self, 'sol_ix_inner_idx', sol_ix_inner_idx)
        object.__setattr__(self, '_str', '')

    def set_block_info(self, block: SolBlockInfo, neon_sig: str, tx_idx: int, log_idx: int) -> int:
        object.__setattr__(self, 'block_slot', block.block_slot)
        object.__setattr__(self, 'block_hash', block.block_hash)
        object.__setattr__(self, 'neon_sig', neon_sig)
        object.__setattr__(self, 'tx_idx', tx_idx)
        object.__setattr__(self, '_str', '')

        hex_block_slot = hex(self.block_slot)
        hex_tx_idx = hex(self.tx_idx)
        tx_log_idx = 0

        for rec in self.log_list:
            rec['transactionHash'] = self.neon_sig
            rec['blockHash'] = self.block_hash
            rec['blockNumber'] = hex_block_slot
            rec['transactionIndex'] = hex_tx_idx
            if not rec['neonIsHidden']:
                rec['logIndex'] = hex(log_idx)
                rec['transactionLogIndex'] = hex(tx_log_idx)
                log_idx += 1
                tx_log_idx += 1

        return log_idx

    def is_valid(self) -> bool:
        return self.gas_used != ''
