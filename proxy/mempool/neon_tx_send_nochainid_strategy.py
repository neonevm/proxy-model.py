from ..common_neon.solana_tx_legacy import SolLegacyTx

from ..mempool.neon_tx_send_holder_strategy import HolderNeonTxStrategy
from ..mempool.neon_tx_send_strategy_base_stages import alt_strategy


class NoChainIdNeonTxStrategy(HolderNeonTxStrategy):
    name = 'TxStepFromAccountNoChainId'

    def _validate(self) -> bool:
        if self._ctx.neon_tx.hasChainId():
            self._validation_error_msg = 'Normal transaction'
            return False
        return True

    def _build_tx(self) -> SolLegacyTx:
        self._uniq_idx += 1
        return self._build_cu_tx(
            self._ctx.ix_builder.make_tx_step_from_account_no_chainid_ix(self._evm_step_cnt, self._uniq_idx)
        )


@alt_strategy
class ALTNoChainIdNeonTxStrategy(NoChainIdNeonTxStrategy):
    pass
