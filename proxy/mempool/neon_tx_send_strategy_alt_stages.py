from typing import List, Optional

from ..common_neon.solana_transaction import SolTx, SolLegacyTx
from ..common_neon.solana_v0_transaction import SolV0Tx
from ..common_neon.solana_alt import ALTInfo
from ..common_neon.solana_alt_builder import ALTTxBuilder, ALTTxSet

from ..mempool.neon_tx_send_base_strategy import BaseNeonTxPrepStage
from ..mempool.neon_tx_sender_ctx import NeonTxSendCtx


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

        alt_builder = ALTTxBuilder(self._ctx.solana, self._ctx.builder, self._ctx.signer)
        self._alt_info = alt_builder.build_alt_info(legacy_tx)
        self._alt_builder = alt_builder
        return True

    def build_prep_tx_list_before_emulate(self) -> List[List[SolTx]]:
        self._alt_tx_set = self._alt_builder.build_alt_tx_set(self._alt_info)
        return self._alt_builder.build_prep_alt_list(self._alt_tx_set)

    def update_after_emulate(self) -> None:
        self._alt_builder.update_alt_info_list([self._alt_info])

    def build_tx(self, legacy_tx: SolLegacyTx) -> SolV0Tx:
        return SolV0Tx(address_table_lookups=[self._alt_info]).add(legacy_tx)


def alt_strategy(cls):
    class ALTStrategy(cls):
        name = 'ALT+' + cls.name

        def __init__(self, ctx: NeonTxSendCtx):
            cls.__init__(self, ctx)
            self._alt_stage = ALTNeonTxPrepStage(ctx)
            self._prep_stage_list.append(self._alt_stage)

        def _validate(self) -> bool:
            return (
                self._alt_stage.init_alt_info(cls._build_tx(self)) and
                cls._validate(self)
            )

        def _build_tx(self) -> SolV0Tx:
            return self._alt_stage.build_tx(cls._build_tx(self))

        def _build_cancel_tx(self) -> SolV0Tx:
            return self._alt_stage.build_tx(cls._build_cancel_tx(self))

    return ALTStrategy
