from ..common_neon.solana_tx_legacy import SolLegacyTx
from ..common_neon.neon_instruction import EvmIxCode, EvmIxCodeName

from .neon_tx_sender_ctx import NeonTxSendCtx
from .neon_tx_send_simple_strategy import SimpleNeonTxStrategy
from .neon_tx_send_strategy_alt_stage import alt_strategy
from .neon_tx_send_strategy_holder_stage import WriteHolderNeonTxPrepStage


class SimpleHolderNeonTxStrategy(SimpleNeonTxStrategy):
    name = EvmIxCodeName().get(EvmIxCode.TxExecFromAccount)

    def __init__(self, ctx: NeonTxSendCtx) -> None:
        super().__init__(ctx)
        self._prep_stage_list.append(WriteHolderNeonTxPrepStage(ctx))

    def _build_tx(self) -> SolLegacyTx:
        return self._build_cu_tx(self._ctx.ix_builder.make_tx_exec_from_account_ix())


@alt_strategy
class ALTSimpleHolderNeonTxStrategy(SimpleHolderNeonTxStrategy):
    pass
