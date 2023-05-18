from ..common_neon.solana_tx_legacy import SolLegacyTx

from ..mempool.neon_tx_sender_ctx import NeonTxSendCtx
from ..mempool.neon_tx_send_iterative_strategy import IterativeNeonTxStrategy
from ..mempool.neon_tx_send_strategy_base_stages import WriteHolderNeonTxPrepStage, alt_strategy


class HolderNeonTxStrategy(IterativeNeonTxStrategy):
    name = 'TxStepFromAccount'

    def __init__(self, ctx: NeonTxSendCtx) -> None:
        super().__init__(ctx)
        self._prep_stage_list.append(WriteHolderNeonTxPrepStage(ctx))

    def _validate(self) -> bool:
        return self._validate_tx_has_chainid()

    def _build_tx(self) -> SolLegacyTx:
        uniq_idx = self._ctx.sol_tx_cnt
        builder = self._ctx.ix_builder

        return self._build_cu_tx(builder.make_tx_step_from_account_ix(self._evm_step_cnt, uniq_idx))


@alt_strategy
class ALTHolderNeonTxStrategy(HolderNeonTxStrategy):
    pass
