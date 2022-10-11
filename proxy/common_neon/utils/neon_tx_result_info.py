from typing import List, Dict, Any, Optional

from .utils import str_fmt_object
from .solana_block import SolanaBlockInfo


class NeonTxResultInfo:
    def __init__(self):
        self.log_list: List[Dict[str, Any]] = []
        self._status = ''
        self._gas_used = ''
        self._return_value = ''
        self._sol_sig: Optional[str] = None
        self._tx_idx: Optional[int] = None
        self._block_slot: Optional[int] = None
        self._block_hash: Optional[str] = None
        self._sol_ix_idx: Optional[int] = None
        self._sol_ix_inner_idx: Optional[int] = None

    @property
    def block_slot(self) -> Optional[int]:
        return self._block_slot

    @property
    def block_hash(self) -> Optional[str]:
        return self._block_hash

    @property
    def tx_idx(self) -> Optional[int]:
        return self._tx_idx

    @property
    def status(self) -> str:
        return self._status

    @property
    def gas_used(self) -> str:
        return self._gas_used

    @property
    def return_value(self) -> str:
        return self._return_value

    @property
    def sol_sig(self) -> Optional[str]:
        return self._sol_sig

    @property
    def sol_ix_idx(self) -> Optional[int]:
        return self._sol_ix_idx

    @property
    def sol_ix_inner_idx(self) -> Optional[int]:
        return self._sol_ix_inner_idx

    def __str__(self) -> str:
        return str_fmt_object(self)

    def __getstate__(self) -> Dict[str, Any]:
        return self.__dict__

    def __setstate__(self, src) -> None:
        self.__dict__ = src

    def append_record(self, rec: Dict[str, Any]) -> None:
        self.log_list.append(rec)

    def fill_result(self, status: str, gas_used: str, return_value: str) -> None:
        self._status = status
        self._gas_used = gas_used
        self._return_value = return_value

    def fill_sol_sig_info(self, sol_sig: str, sol_ix_idx: int, sol_ix_inner_idx: Optional[int]) -> None:
        self._sol_sig = sol_sig
        self._sol_ix_idx = sol_ix_idx
        self._sol_ix_inner_idx = sol_ix_inner_idx

    def fill_block_info(self, block: SolanaBlockInfo, tx_idx: int, log_idx: int) -> None:
        hex_block_slot = hex(block.block_slot)
        hex_tx_idx = hex(tx_idx)

        self._block_slot = block.block_slot
        self._block_hash = block.block_hash
        self._tx_idx = tx_idx
        for rec in self.log_list:
            rec['blockHash'] = block.block_hash
            rec['blockNumber'] = hex_block_slot
            rec['transactionIndex'] = hex_tx_idx
            rec['logIndex'] = hex(log_idx)
            log_idx += 1

    def is_valid(self) -> bool:
        return self._gas_used != ''
