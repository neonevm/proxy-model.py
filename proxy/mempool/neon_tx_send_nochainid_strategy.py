from ..common_neon.solana_tx_legacy import SolLegacyTx

from ..mempool.neon_tx_send_holder_strategy import HolderNeonTxStrategy
from ..mempool.neon_tx_send_strategy_base_stages import alt_strategy


class NoChainIdNeonTxStrategy(HolderNeonTxStrategy):
    name = 'TxStepFromAccountNoChainId'

    def _validate(self) -> bool:
        if self._ctx.neon_tx_info.has_chain_id():
            self._validation_error_msg = 'Normal transaction'
            return False
        return True

    def _build_tx(self) -> SolLegacyTx:
        uniq_idx = self.ctx.sol_tx_cnt
        builder = self._ctx.ix_builder

        return self._build_cu_tx(builder.make_tx_step_from_account_no_chainid_ix(self._evm_step_cnt, uniq_idx))


@alt_strategy
class ALTNoChainIdNeonTxStrategy(NoChainIdNeonTxStrategy):
    pass
