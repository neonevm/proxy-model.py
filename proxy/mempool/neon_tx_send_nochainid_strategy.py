from ..common_neon.solana_transaction import SolLegacyTx

from ..mempool.neon_tx_send_base_strategy import BaseNeonTxStrategy
from ..mempool.neon_tx_send_holder_strategy import HolderNeonTxStrategy
from ..mempool.neon_tx_send_strategy_base_stages import alt_strategy


class NoChainIdNeonTxStrategy(HolderNeonTxStrategy):
    name = 'TransactionStepFromAccountNoChainId'

    def _validate(self) -> bool:
        if self._ctx.neon_tx.hasChainId():
            self._validation_error_msg = 'Normal transaction'
            return False
        return True

    def _build_tx(self) -> SolLegacyTx:
        self._uniq_idx += 1
        return BaseNeonTxStrategy._build_tx(self).add(
            self._ctx.ix_builder.make_tx_step_from_account_no_chainid_ix(self._evm_step_cnt, self._uniq_idx)
        )


@alt_strategy
class ALTNoChainIdNeonTxStrategy(NoChainIdNeonTxStrategy):
    pass
