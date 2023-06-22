from __future__ import annotations

import abc
import dataclasses
import logging

from typing import Dict, Iterator, Optional, Any, Tuple, Union, List

from ..common_neon.address import NeonAddress
from ..common_neon.config import Config
from ..common_neon.neon_instruction import EvmIxCode
from ..common_neon.utils.evm_log_decoder import NeonLogTxEvent
from ..common_neon.solana_neon_tx_receipt import SolNeonIxReceiptInfo
from ..common_neon.utils.neon_tx_info import NeonTxInfo

from ..indexer.indexed_objects import NeonIndexedTxInfo


LOG = logging.getLogger(__name__)


class GasTankTxInfo(NeonIndexedTxInfo):
    def __init__(self, ix_code: EvmIxCode, key: NeonIndexedTxInfo.Key, neon_tx: NeonTxInfo,
                 operator: str, holder: str, blocked_acct_list: List[str]):
        super().__init__(ix_code, key, neon_tx, holder, blocked_acct_list)
        self.operator = operator
        self.iterations: Dict[int, int] = {}

    @staticmethod
    def create_tx_info(neon_tx_sig: str, message: bytes, ix_code: EvmIxCode, key: NeonIndexedTxInfo.Key,
                       operator: str, holder: str, iter_blocked_account: Iterator[str]) -> Optional[GasTankTxInfo]:
        neon_tx = NeonTxInfo.from_sig_data(message)
        if neon_tx.error:
            LOG.warning(f'Neon tx rlp error "{neon_tx.error}"')
            return None
        if neon_tx_sig != neon_tx.sig:
            LOG.warning(f'Neon tx hash {neon_tx.sig} != {neon_tx_sig}')
            return None

        blocked_account_list = list(iter_blocked_account)
        return GasTankTxInfo(ix_code, key, neon_tx, operator, holder, blocked_account_list)

    def append_receipt(self, ix: SolNeonIxReceiptInfo):
        self.iterations[ix.neon_total_gas_used] = ix.neon_gas_used
        self.add_sol_neon_ix(ix)
        total_gas_used = ix.neon_total_gas_used
        for event in ix.neon_tx_event_list:
            self.add_neon_event(dataclasses.replace(
                event,
                total_gas_used=total_gas_used,
                sol_sig=ix.sol_sig,
                idx=ix.idx,
                inner_idx=ix.inner_idx
            ))
            total_gas_used += 1

        if ix.neon_tx_return is not None:
            self.neon_tx_res.set_res(status=ix.neon_tx_return.status, gas_used=ix.neon_tx_return.gas_used)
            self.neon_tx_res.set_sol_sig_info(ix.sol_sig, ix.idx, ix.inner_idx)
            self.add_neon_event(NeonLogTxEvent(
                event_type=NeonLogTxEvent.Type.Return,
                is_hidden=True, address=b'', topic_list=[],
                data=ix.neon_tx_return.status.to_bytes(1, 'little'),
                total_gas_used=ix.neon_tx_return.gas_used + 5000,
                sol_sig=ix.sol_sig, idx=ix.idx, inner_idx=ix.inner_idx
            ))
            self.mark_done(ix.block_slot)

    def finalize(self):
        total_gas_used = 0
        for k, v in sorted(self.iterations.items()):
            if total_gas_used + v != k:
                raise Exception(f'{self.key} not all iterations were collected {sorted(self.iterations.items())}')
            total_gas_used += v

        self.complete_event_list()

    def iter_events(self) -> Iterator[Dict[str, Any]]:
        for ev in self.neon_tx_res.log_list:
            if not ev['neonIsHidden']:
                yield ev


# Base class to create NeonEVM transaction analyzers for gas-tank
class GasTankNeonTxAnalyzer(abc.ABC):
    name = 'UNKNOWN'

    # token_whitelist - the white list of tokens, transfers to which lead to gas-less transactions.
    def __init__(self, config: Config, token_whitelist: Union[bool, Dict[str, int]]):
        self._config = config
        self._token_whitelist = token_whitelist
        if isinstance(self._token_whitelist, bool) and self._token_whitelist:
            self._has_token_whitelist = True
        else:
            self._has_token_whitelist = len(self._token_whitelist) > 0

    # Function to process NeonEVM transaction to find one that should be allowed with gas-less transactions
    # Arguments:
    #  - neon_tx - information about NeonEVM transaction
    @abc.abstractmethod
    def process(self, neon_tx: GasTankTxInfo) -> Optional[NeonAddress]:
        pass

    def _is_allowed_token(self, token: str, amount: int) -> bool:
        if isinstance(self._token_whitelist, bool):
            return True

        min_amount = self._token_whitelist.get(token, None)
        if min_amount is None:
            return False
        return min_amount <= amount


class GasTankSolTxAnalyzer(abc.ABC):
    name = 'UNKNOWN'

    def __init__(self, config: Config, token_whitelist: Union[bool, Dict[str, int]]):
        self._config = config
        self._token_whitelist = token_whitelist
        if isinstance(self._token_whitelist, bool) and self._token_whitelist:
            self._has_token_whitelist = True
        else:
            self._has_token_whitelist = len(self._token_whitelist) > 0

    @abc.abstractmethod
    def process(self, sol_tx: Dict[str, Any]) -> List[Tuple[NeonAddress, NeonTxInfo]]:
        pass

    def _is_allowed_contract(self, token: str, amount: int) -> bool:
        if isinstance(self._token_whitelist, bool):
            return True

        min_amount = self._token_whitelist.get(token, None)
        if min_amount is None:
            return False
        return min_amount <= amount


@dataclasses.dataclass(frozen=True)
class GasLessPermit:
    account: NeonAddress
    block_slot: int
    neon_sig: str
    nonce: int = 0
    contract: Optional[NeonAddress] = None


@dataclasses.dataclass(frozen=True)
class GasLessUsage:
    account: NeonAddress
    block_slot: int
    neon_sig: str
    nonce: int
    to_addr: Optional[NeonAddress]
    neon_total_gas_usage: int
    operator: str
