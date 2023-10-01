import logging

from typing import List, Generator

from ..common_neon.solana_tx_legacy import SolLegacyTx
from ..common_neon.solana_tx_list_sender import SolTxSendState
from ..common_neon.neon_tx_result_info import NeonTxResultInfo
from ..common_neon.solana_tx_error_parser import SolTxError
from ..common_neon.neon_instruction import EvmIxCode, EvmIxCodeName
from ..common_neon.errors import WrongStrategyError

from .neon_tx_sender_ctx import NeonTxSendCtx
from .neon_tx_send_base_strategy import BaseNeonTxStrategy
from .neon_tx_send_strategy_alt_stage import alt_strategy
from .neon_tx_send_strategy_newaccount_stage import NewAccountNeonTxPrepStage


LOG = logging.getLogger(__name__)


class SimpleNeonTxStrategy(BaseNeonTxStrategy):
    name = EvmIxCodeName().get(EvmIxCode.TxExecFromData)

    def __init__(self, ctx: NeonTxSendCtx) -> None:
        super().__init__(ctx)
        self._prep_stage_list.append(NewAccountNeonTxPrepStage(ctx))

    def execute(self) -> NeonTxResultInfo:
        assert self.is_valid()

        try:
            if not self._recheck_tx_list([self.name]):
                self._send_tx_list(self._build_tx_list())

        except SolTxError as err:
            LOG.debug(f'Got error {str(err)}, use another strategy for execution')
            raise WrongStrategyError()

        except (BaseException,):
            raise

        tx_send_state_list = self._sol_tx_list_sender.tx_state_list
        tx_state = tx_send_state_list[0]
        neon_tx_res = NeonTxResultInfo()
        status = SolTxSendState.Status

        if tx_state.status == status.GoodReceipt:
            sol_neon_ix = self._find_sol_neon_ix(tx_state)
            ret = sol_neon_ix.neon_tx_return
            if ret is not None:
                neon_tx_res.set_res(status=ret.status, gas_used=ret.gas_used)
                LOG.debug(f'Set Neon tx result: {neon_tx_res}')

            else:
                neon_tx_res.set_lost_res(sol_neon_ix.neon_total_gas_used)
                LOG.debug(f'Set truncated Neon tx result: {neon_tx_res}')

        else:
            LOG.debug(f'Cannot find NeonTx receipt, use another strategy for execution')
            raise WrongStrategyError()

        return neon_tx_res

    def cancel(self) -> None:
        LOG.error('canceling of simple Neon tx')

    def _build_tx_list(self) -> Generator[List[SolLegacyTx], None, None]:
        yield [self._build_tx()]

    def _build_tx(self) -> SolLegacyTx:
        return self._build_cu_tx(self._ctx.ix_builder.make_tx_exec_from_data_ix())

    def _validate(self) -> bool:
        return (
            self._validate_stuck_tx() and
            self._validate_tx_has_chainid() and
            self._validate_no_resize_iter_cnt()
        )

    def _validate_no_resize_iter_cnt(self) -> bool:
        if self._ctx.resize_iter_cnt <= 0:
            return True
        self._validation_error_msg = 'Has account resize iterations'
        return False


@alt_strategy
class ALTSimpleNeonTxStrategy(SimpleNeonTxStrategy):
    pass
