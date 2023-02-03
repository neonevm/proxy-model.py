from ..common_neon.solana_tx_legacy import SolLegacyTx

from ..mempool.neon_tx_sender_ctx import NeonTxSendCtx
from ..mempool.neon_tx_send_simple_strategy import SimpleNeonTxStrategy
from ..mempool.neon_tx_send_strategy_base_stages import WriteHolderNeonTxPrepStage, alt_strategy


class SimpleHolderNeonTxStrategy(SimpleNeonTxStrategy):
    name = 'TxExecFromAccount'

    def __init__(self, ctx: NeonTxSendCtx) -> None:
        super().__init__(ctx)
        self._prep_stage_list.append(WriteHolderNeonTxPrepStage(ctx))

    def _build_tx(self) -> SolLegacyTx:
        return self._build_cu_tx(self._ctx.ix_builder.make_tx_exec_from_account_ix())


@alt_strategy
class ALTSimpleHolderNeonTxStrategy(SimpleHolderNeonTxStrategy):
    pass
