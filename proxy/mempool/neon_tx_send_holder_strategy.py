from ..common_neon.solana_transaction import SolLegacyTx

from ..mempool.neon_tx_sender_ctx import NeonTxSendCtx
from ..mempool.neon_tx_send_base_strategy import BaseNeonTxStrategy
from ..mempool.neon_tx_send_iterative_strategy import IterativeNeonTxStrategy
from ..mempool.neon_tx_send_strategy_base_stages import WriteHolderNeonTxPrepStage, alt_strategy


class HolderNeonTxStrategy(IterativeNeonTxStrategy):
    name = 'TransactionStepFromAccount'

    def __init__(self, ctx: NeonTxSendCtx) -> None:
        super().__init__(ctx)
        self._prep_stage_list.append(WriteHolderNeonTxPrepStage(ctx))

    def _validate(self) -> bool:
        return self._validate_tx_has_chainid()

    def _build_tx(self) -> SolLegacyTx:
        self._uniq_idx += 1
        return BaseNeonTxStrategy._build_tx(self).add(
            self._ctx.ix_builder.make_tx_step_from_account_ix(self._evm_step_cnt, self._uniq_idx)
        )


@alt_strategy
class ALTHolderNeonTxStrategy(HolderNeonTxStrategy):
    pass
