import copy

from typing import List

from ..common_neon.solana_transaction import SolTx, SolLegacyTx, SolWrappedTx
from ..common_neon.elf_params import ElfParams

from ..mempool.neon_tx_send_base_strategy import BaseNeonTxPrepStage


class CreateAccountNeonTxPrepStage(BaseNeonTxPrepStage):
    def build_prep_tx_list_before_emulate(self) -> List[List[SolTx]]:
        tx_list = self._ctx.account_tx_list_builder.get_tx_list()
        if len(tx_list) == 0:
            return []
        return [tx_list]

    def update_after_emulate(self) -> None:
        self._ctx.account_tx_list_builder.clear_tx_list()


class WriteHolderNeonTxPrepStage(BaseNeonTxPrepStage):
    def build_prep_tx_list_before_emulate(self) -> List[List[SolTx]]:
        if self._ctx.is_holder_completed:
            return []

        tx_list: List[SolTx] = []
        holder_msg_offset = 0
        holder_msg = copy.copy(self._ctx.ix_builder.holder_msg)
        neon_tx_sig = self._ctx.bin_neon_sig

        holder_msg_size = ElfParams().holder_msg_size
        while len(holder_msg):
            (holder_msg_part, holder_msg) = (holder_msg[:holder_msg_size], holder_msg[holder_msg_size:])
            tx = SolLegacyTx().add(self._ctx.ix_builder.make_write_ix(neon_tx_sig, holder_msg_offset, holder_msg_part))
            tx_list.append(SolWrappedTx(tx=tx, name='WriteHolderAccount'))
            holder_msg_offset += holder_msg_size

        return [tx_list]

    def update_after_emulate(self) -> None:
        self._ctx.set_holder_completed()
