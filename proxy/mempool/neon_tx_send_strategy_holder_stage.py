import copy
import logging

from typing import List, Dict, Union

from ..common_neon.constants import EMPTY_HOLDER_TAG, ACTIVE_HOLDER_TAG, FINALIZED_HOLDER_TAG, HOLDER_TAG
from ..common_neon.elf_params import ElfParams
from ..common_neon.errors import BadResourceError, HolderContentError, StuckTxError
from ..common_neon.solana_tx import SolTx
from ..common_neon.solana_tx_legacy import SolLegacyTx
from ..common_neon.layouts import HolderAccountInfo
from ..common_neon.data import NeonEmulatedResult
from ..common_neon.neon_instruction import EvmIxCodeName, EvmIxCode

from .neon_tx_send_base_strategy import BaseNeonTxPrepStage


LOG = logging.getLogger(__name__)


class WriteHolderNeonTxPrepStage(BaseNeonTxPrepStage):
    name = EvmIxCodeName().get(EvmIxCode.HolderWrite)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._holder_tag = EMPTY_HOLDER_TAG

    @property
    def holder_tag(self) -> int:
        return self._holder_tag

    def complete_init(self) -> None:
        if not self._ctx.is_stuck_tx():
            self._ctx.mark_resource_use()

    def _validate_holder_account(self) -> None:
        holder_info = self._get_holder_account_info()
        holder_acct = holder_info.holder_account
        self._holder_tag = holder_info.tag

        if holder_info.tag == FINALIZED_HOLDER_TAG:
            if not self._ctx.has_sol_tx(self.name):
                return
            elif holder_info.neon_tx_sig != self._ctx.neon_tx_info.sig:
                HolderContentError(str(holder_acct))

        elif holder_info.tag == ACTIVE_HOLDER_TAG:
            if holder_info.neon_tx_sig != self._ctx.neon_tx_info.sig:
                raise StuckTxError(holder_info.neon_tx_sig, str(holder_acct))

        elif holder_info.tag == HOLDER_TAG:
            if not self._ctx.has_sol_tx(self.name):
                return

            builder = self._ctx.ix_builder
            holder_msg_len = len(builder.holder_msg)
            if builder.holder_msg != holder_info.neon_tx_data[:holder_msg_len]:
                HolderContentError(str(holder_acct))

    def validate_stuck_tx(self) -> None:
        holder_info = self._get_holder_account_info()
        holder_acct = holder_info.holder_account
        self._holder_tag = holder_info.tag

        if holder_info.tag == FINALIZED_HOLDER_TAG:
            pass

        elif holder_info.tag == ACTIVE_HOLDER_TAG:
            if holder_info.neon_tx_sig != self._ctx.neon_tx_info.sig:
                self._holder_tag = FINALIZED_HOLDER_TAG
                LOG.debug(f'NeonTx in {str(holder_acct)} was finished...')
            else:
                self._read_blocked_account_list(holder_info)

        elif holder_info.tag == HOLDER_TAG:
            self._holder_tag = FINALIZED_HOLDER_TAG
            LOG.debug(f'NeonTx in {str(holder_acct)} was finished...')

    def _read_blocked_account_list(self, holder_info: HolderAccountInfo) -> None:
        acct_list: List[Dict[str, Union[bool, str]]] = list()
        for acct in holder_info.account_list:
            acct_list.append(dict(
                pubkey=acct.pubkey,
                is_writable=acct.is_writable
            ))

        emulated_result: NeonEmulatedResult = dict(
            accounts=list(),
            solana_accounts=acct_list,
            steps_executed=1
        )

        self._ctx.set_emulated_result(emulated_result)

    def _get_holder_account_info(self) -> HolderAccountInfo:
        holder_account = self._ctx.holder_account

        holder_info = self._ctx.solana.get_holder_account_info(holder_account)
        if holder_info is None:
            raise BadResourceError(f'Bad holder account {str(holder_account)}')
        elif holder_info.tag not in {FINALIZED_HOLDER_TAG, ACTIVE_HOLDER_TAG, HOLDER_TAG}:
            raise BadResourceError(f'Holder account {str(holder_account)} has bad tag: {holder_info.tag}')

        self._holder_tag = holder_info.tag
        return holder_info

    def get_tx_name_list(self) -> List[str]:
        if self._ctx.is_stuck_tx():
            return list()
        return [self.name]

    def build_tx_list(self) -> List[List[SolTx]]:
        if self._ctx.is_stuck_tx() or self._ctx.has_sol_tx(self.name):
            return list()

        builder = self._ctx.ix_builder

        tx_list: List[SolTx] = list()
        holder_msg_offset = 0
        holder_msg = copy.copy(builder.holder_msg)

        holder_msg_size = ElfParams().holder_msg_size
        while len(holder_msg):
            (holder_msg_part, holder_msg) = (holder_msg[:holder_msg_size], holder_msg[holder_msg_size:])
            tx = SolLegacyTx(
                name=self.name,
                ix_list=[builder.make_write_ix(holder_msg_offset, holder_msg_part)]
            )
            tx_list.append(tx)
            holder_msg_offset += holder_msg_size

        return [tx_list]

    def update_holder_tag(self) -> None:
        if self._ctx.is_stuck_tx():
            self.validate_stuck_tx()
        else:
            self._validate_holder_account()

    def update_after_emulate(self) -> None:
        self.update_holder_tag()
