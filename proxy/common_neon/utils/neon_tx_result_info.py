from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .solana_block import SolanaBlockInfo
from .utils import str_fmt_object


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
    return_value: str = ''

    log_list: List[Dict[str, Any]] = None

    _str = ''

    def __post_init__(self):
        object.__setattr__(self, 'log_list', [])

    def __str__(self) -> str:
        if self._str == '':
            object.__setattr__(self, '_str', str_fmt_object(self))
        return self._str

    def add_event(self, address: bytes, topic_list: List[bytes], log_data: bytes) -> None:
        rec = {
            'address': '0x' + address.hex(),
            'topics': ['0x' + topic.hex() for topic in topic_list],
            'data': '0x' + log_data.hex(),
            'transactionLogIndex': hex(len(self.log_list)),
            # 'logIndex': hex(tx_log_idx), # set when transaction found
            # 'transactionIndex': hex(ix.idx), # set when transaction found
            # 'blockNumber': block_number, # set when transaction found
            # 'blockHash': block_hash # set when transaction found
        }

        self.log_list.append(rec)
        object.__setattr__(self, '_str', '')

    def set_result(self, status: int, gas_used: int, return_value: bytes) -> None:
        object.__setattr__(self, 'status', hex(status))
        object.__setattr__(self, 'gas_used', hex(gas_used))
        object.__setattr__(self, 'return_value', '0x' + return_value.hex())
        object.__setattr__(self, '_str', '')

    def set_sol_sig_info(self, sol_sig: str, sol_ix_idx: int, sol_ix_inner_idx: Optional[int]) -> None:
        object.__setattr__(self, 'sol_sig', sol_sig)
        object.__setattr__(self, 'sol_ix_idx', sol_ix_idx)
        object.__setattr__(self, 'sol_ix_inner_idx', sol_ix_inner_idx)
        object.__setattr__(self, '_str', '')

    def set_block_info(self, block: SolanaBlockInfo, neon_sig: str, tx_idx: int, log_idx: int) -> None:
        hex_block_slot = hex(block.block_slot)
        hex_tx_idx = hex(tx_idx)

        object.__setattr__(self, 'block_slot', block.block_slot)
        object.__setattr__(self, 'block_hash', block.block_hash)
        object.__setattr__(self, 'tx_idx', tx_idx)
        object.__setattr__(self, '_str', '')

        for rec in self.log_list:
            rec['transactionHash'] = neon_sig
            rec['blockHash'] = block.block_hash
            rec['blockNumber'] = hex_block_slot
            rec['transactionIndex'] = hex_tx_idx
            rec['logIndex'] = hex(log_idx)
            log_idx += 1

    def is_valid(self) -> bool:
        return self.gas_used != ''
