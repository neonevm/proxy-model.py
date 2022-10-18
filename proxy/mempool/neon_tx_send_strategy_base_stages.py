import copy

from typing import List, Optional

from ..common_neon.solana_tx import SolTx
from ..common_neon.solana_tx_legacy import SolLegacyTx
from ..common_neon.solana_tx_v0 import SolV0Tx
from ..common_neon.solana_alt import ALTInfo
from ..common_neon.solana_alt_builder import ALTTxBuilder, ALTTxSet
from ..common_neon.elf_params import ElfParams

from ..mempool.neon_tx_send_base_strategy import BaseNeonTxPrepStage
from ..mempool.neon_tx_sender_ctx import NeonTxSendCtx


class WriteHolderNeonTxPrepStage(BaseNeonTxPrepStage):
    def build_prep_tx_list_before_emulate(self) -> List[List[SolTx]]:
        if self._ctx.is_holder_completed:
            return []

        builder = self._ctx.ix_builder

        tx_list: List[SolTx] = []
        holder_msg_offset = 0
        holder_msg = copy.copy(builder.holder_msg)
        neon_tx_sig = self._ctx.bin_neon_sig

        holder_msg_size = ElfParams().holder_msg_size
        while len(holder_msg):
            (holder_msg_part, holder_msg) = (holder_msg[:holder_msg_size], holder_msg[holder_msg_size:])
            tx = SolLegacyTx(
                name='WriteHolderAccount',
                instructions=[builder.make_write_ix(neon_tx_sig, holder_msg_offset, holder_msg_part)]
            )
            tx_list.append(tx)
            holder_msg_offset += holder_msg_size

        return [tx_list]

    def update_after_emulate(self) -> None:
        self._ctx.set_holder_completed()


class ALTNeonTxPrepStage(BaseNeonTxPrepStage):
    def __init__(self, ctx: NeonTxSendCtx):
        super().__init__(ctx)
        self._alt_info: Optional[ALTInfo] = None
        self._alt_builder: Optional[ALTTxBuilder] = None
        self._alt_tx_set: Optional[ALTTxSet] = None

    def init_alt_info(self, legacy_tx: SolLegacyTx) -> bool:
        # TODO: if there are a lot of changes in the account list, the alt should be regenerated
        if self._alt_info is not None:
            return True

        alt_builder = ALTTxBuilder(self._ctx.solana, self._ctx.ix_builder, self._ctx.signer)
        alt_info = alt_builder.build_alt_info(legacy_tx)

        self._alt_info = alt_info
        self._alt_builder = alt_builder
        self._alt_tx_set = self._alt_builder.build_alt_tx_set(self._alt_info)
        return True

    def build_prep_tx_list_before_emulate(self) -> List[List[SolTx]]:
        return self._alt_builder.build_prep_alt_list(self._alt_tx_set)

    def update_after_emulate(self) -> None:
        self._alt_tx_set.clear()
        self._alt_builder.update_alt_info_list([self._alt_info])

    def build_tx(self, legacy_tx: SolLegacyTx) -> SolV0Tx:
        return SolV0Tx(name=legacy_tx.name, address_table_lookups=[self._alt_info]).add(legacy_tx)


def alt_strategy(cls):
    class ALTStrategy(cls):
        name = 'ALT+' + cls.name

        def __init__(self, ctx: NeonTxSendCtx):
            cls.__init__(self, ctx)
            self._alt_stage = ALTNeonTxPrepStage(ctx)
            self._prep_stage_list.append(self._alt_stage)

        def _validate(self) -> bool:
            return (
                self._validate_account_list_len() and
                self._alt_stage.init_alt_info(cls._build_tx(self)) and
                cls._validate(self)
            )

        def _validate_account_list_len(self) -> bool:
            account_list_len = self._ctx.len_account_list() + 6
            if account_list_len < ALTTxBuilder.tx_account_cnt:
                self._validation_error_msg = (
                    f'Number of accounts {account_list_len} '
                    f'less than {ALTTxBuilder.tx_account_cnt}'
                )
                return False
            return True

        def _build_tx(self) -> SolV0Tx:
            return self._alt_stage.build_tx(cls._build_tx(self))

        def _build_cancel_tx(self) -> SolV0Tx:
            return self._alt_stage.build_tx(cls._build_cancel_tx(self))

    return ALTStrategy
