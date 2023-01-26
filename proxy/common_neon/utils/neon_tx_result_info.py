from typing import List, Dict, Any, Optional
from dataclasses import dataclass

import logging

from .solana_block import SolanaBlockInfo
from .utils import str_fmt_object


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

    _tx_log_idx: int = 0

    _str = ''

    def __post_init__(self):
        object.__setattr__(self, 'log_list', [])

    def __str__(self) -> str:
        if self._str == '':
            object.__setattr__(self, '_str', str_fmt_object(self))
        return self._str

    def add_event(self, event_type: int, address: bytes, topic_list: List[bytes], log_data: bytes,
                  sol_sig: str, idx: int, inner_idx: Optional[int],
                  is_hidden: bool, is_reverted: bool, event_level: int, event_order: int) -> None:
        if self.block_slot is not None:
            LOG.warning(f'Neon tx {self.neon_sig} has completed event logs')
            return

        rec = {
            'address': '0x' + address.hex() if len(address) > 0 else '',
            'topics': ['0x' + topic.hex() for topic in topic_list],
            'data': '0x' + log_data.hex() if len(log_data) > 0 else '',
            'transactionLogIndex': hex(self._tx_log_idx),

            'solHash': sol_sig,
            'ixIdx': hex(idx),
            'innerIxIdx': None if inner_idx is None else hex(inner_idx),
            'eventType': event_type,
            'eventLevel': hex(event_level),
            'eventOrder': hex(event_order),
            'isHidden': is_hidden,
            'isReverted': is_reverted,

            # 'logIndex': hex(tx_log_idx), # set when transaction found
            # 'transactionIndex': hex(ix.idx), # set when transaction found
            # 'blockNumber': block_number, # set when transaction found
            # 'blockHash': block_hash # set when transaction found
        }

        if not is_hidden:
            object.__setattr__(self, '_tx_log_idx', self._tx_log_idx + 1)

        self.log_list.append(rec)
        object.__setattr__(self, '_str', '')

    def set_result(self, status: int, gas_used: int) -> None:
        object.__setattr__(self, 'status', hex(status))
        object.__setattr__(self, 'gas_used', hex(gas_used))
        object.__setattr__(self, '_str', '')

    def set_sol_sig_info(self, sol_sig: str, sol_ix_idx: int, sol_ix_inner_idx: Optional[int]) -> None:
        object.__setattr__(self, 'sol_sig', sol_sig)
        object.__setattr__(self, 'sol_ix_idx', sol_ix_idx)
        object.__setattr__(self, 'sol_ix_inner_idx', sol_ix_inner_idx)
        object.__setattr__(self, '_str', '')

    def set_block_info(self, block: SolanaBlockInfo, neon_sig: str, tx_idx: int, log_idx: int) -> int:
        object.__setattr__(self, 'block_slot', block.block_slot)
        object.__setattr__(self, 'block_hash', block.block_hash)
        object.__setattr__(self, 'neon_sig', neon_sig)
        object.__setattr__(self, 'tx_idx', tx_idx)
        object.__setattr__(self, '_str', '')

        hex_block_slot = hex(self.block_slot)
        hex_tx_idx = hex(self.tx_idx)

        for rec in self.log_list:
            rec['transactionHash'] = self.neon_sig
            rec['blockHash'] = self.block_hash
            rec['blockNumber'] = hex_block_slot
            rec['transactionIndex'] = hex_tx_idx
            if not rec['isHidden']:
                rec['logIndex'] = hex(log_idx)
                log_idx += 1

        return log_idx

    def is_valid(self) -> bool:
        return self.gas_used != ''
