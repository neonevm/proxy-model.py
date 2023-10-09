from ..common_neon.solana_tx_legacy import SolLegacyTx
from ..common_neon.neon_tx_result_info import NeonTxResultInfo
from ..common_neon.neon_instruction import EvmIxCode, EvmIxCodeName

from ..neon_core_api.neon_layouts import HolderStatus

from .neon_tx_sender_ctx import NeonTxSendCtx
from .neon_tx_send_iterative_strategy import IterativeNeonTxStrategy
from .neon_tx_send_strategy_alt_stage import alt_strategy
from .neon_tx_send_strategy_holder_stage import WriteHolderNeonTxPrepStage


class HolderNeonTxStrategy(IterativeNeonTxStrategy):
    name = EvmIxCodeName().get(EvmIxCode.TxStepFromAccount)

    def __init__(self, ctx: NeonTxSendCtx) -> None:
        super().__init__(ctx)
        self._write_holder_stage = WriteHolderNeonTxPrepStage(ctx)
        self._prep_stage_list.append(self._write_holder_stage)

    def _validate(self) -> bool:
        if self._ctx.is_stuck_tx():
            self._write_holder_stage.validate_stuck_tx()
        return self._validate_tx_has_chainid()

    def _build_tx(self) -> SolLegacyTx:
        uniq_idx = self._ctx.sol_tx_cnt
        builder = self._ctx.ix_builder

        return self._build_cu_tx(builder.make_tx_step_from_account_ix(self._evm_step_cnt, uniq_idx))

    def execute(self) -> NeonTxResultInfo:
        if (not self._ctx.has_sol_tx(self.name)) and (self._write_holder_stage.holder_status == HolderStatus.Finalized):
            neon_tx_res = NeonTxResultInfo()
            neon_tx_res.set_lost_res()
            return neon_tx_res

        return super().execute()

    def _decode_neon_tx_result(self) -> NeonTxResultInfo:
        neon_tx_res = super()._decode_neon_tx_result()
        if neon_tx_res.is_valid():
            return neon_tx_res

        self._write_holder_stage.update_holder_tag()
        if self._write_holder_stage.holder_status == HolderStatus.Finalized:
            neon_tx_res.set_lost_res()
        return neon_tx_res


@alt_strategy
class ALTHolderNeonTxStrategy(HolderNeonTxStrategy):
    pass
