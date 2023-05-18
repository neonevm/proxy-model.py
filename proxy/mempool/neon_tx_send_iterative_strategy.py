import logging

from typing import List, Generator

from ..common_neon.errors import NoMoreRetriesError
from ..common_neon.solana_tx import SolTx
from ..common_neon.solana_tx_legacy import SolLegacyTx
from ..common_neon.solana_tx_list_sender import SolTxSendState
from ..common_neon.utils import NeonTxResultInfo

from ..mempool.neon_tx_send_base_strategy import BaseNeonTxStrategy
from ..mempool.neon_tx_send_strategy_base_stages import alt_strategy


LOG = logging.getLogger(__name__)


class IterativeNeonTxStrategy(BaseNeonTxStrategy):
    name = 'TxStepFromData'
    _cancel_name = 'CancelWithHash'

    def complete_init(self) -> None:
        super().complete_init()
        self._ctx.set_holder_usage(True)

    def execute(self) -> NeonTxResultInfo:
        self._sol_tx_list_sender.clear()

        assert self.is_valid()

        self._send_tx_list([self.name], self._build_execute_tx_list())

        # Not enough iterations, try `retry_on_fail` times to complete the Neon Tx
        retry_on_fail = self._ctx.config.retry_on_fail
        for retry in range(retry_on_fail):
            neon_tx_res = self._decode_neon_tx_result()
            if neon_tx_res.is_valid():
                return neon_tx_res

            self._send_tx_list([], self._build_complete_tx_list())

        raise NoMoreRetriesError()

    def cancel(self) -> None:
        self._send_tx_list([self._cancel_name], self._build_cancel_tx_list())

    def _build_execute_tx_list(self) -> Generator[List[SolTx], None, None]:
        LOG.debug(
            f'Total EVM steps {self._ctx.emulated_evm_step_cnt}, '
            f'total resize iterations {self._ctx.resize_iter_cnt}'
        )

        emulated_step_cnt = max(self._ctx.emulated_evm_step_cnt, self._evm_step_cnt)
        additional_iter_cnt = self._ctx.resize_iter_cnt
        additional_iter_cnt += 2  # `begin` and `finalization` iterations

        yield from self._build_tx_list_impl(emulated_step_cnt, additional_iter_cnt)

    def _build_complete_tx_list(self) -> Generator[List[SolTx], None, None]:
        LOG.debug('No receipt -> execute additional iteration')
        yield from self._build_tx_list_impl(0, 1)

    def _build_tx_list_impl(self, total_evm_step_cnt: int, add_iter_cnt: int) -> Generator[List[SolTx], None, None]:
        tx_list: List[SolTx] = list()

        for _ in range(add_iter_cnt):
            tx_list.append(self._build_tx())

        remain_evm_step_cnt = total_evm_step_cnt
        while remain_evm_step_cnt > 0:
            remain_evm_step_cnt -= self._evm_step_cnt
            tx_list.append(self._build_tx())

        LOG.debug(
            f'Total iterations: {len(tx_list)}, '
            f'additional iterations: {add_iter_cnt}, '
            f'total EVM steps: {total_evm_step_cnt}, '
            f'EVM steps per iteration: {self._evm_step_cnt}'
        )
        yield tx_list

    def _validate(self) -> bool:
        return self._validate_tx_has_chainid()

    def _build_tx(self) -> SolLegacyTx:
        uniq_idx = self._ctx.sol_tx_cnt
        builder = self._ctx.ix_builder
        return self._build_cu_tx(builder.make_tx_step_from_data_ix(self._evm_step_cnt, uniq_idx))

    def _build_cancel_tx(self) -> SolLegacyTx:
        return self._build_cu_tx(name='CancelWithHash', ix=self._ctx.ix_builder.make_cancel_ix())

    def _decode_neon_tx_result(self) -> NeonTxResultInfo:
        neon_tx_res = NeonTxResultInfo()
        tx_send_state_list = self._sol_tx_list_sender.tx_state_list
        neon_total_gas_used = 0
        has_already_finalized = False
        status = SolTxSendState.Status

        for tx_send_state in tx_send_state_list:
            if tx_send_state.status == status.AlreadyFinalizedError:
                has_already_finalized = True
                continue
            elif tx_send_state.status != status.GoodReceipt:
                continue

            sol_neon_ix = self._find_sol_neon_ix(tx_send_state)
            if sol_neon_ix is None:
                continue

            neon_total_gas_used = max(neon_total_gas_used, sol_neon_ix.neon_total_gas_used)

            ret = sol_neon_ix.neon_tx_return
            if ret is None:
                continue

            neon_tx_res.set_res(status=ret.status, gas_used=ret.gas_used)
            LOG.debug(f'Set Neon tx result: {neon_tx_res}')
            return neon_tx_res

        if has_already_finalized:
            neon_tx_res.set_lost_res(neon_total_gas_used)
            LOG.debug(f'Set lost Neon tx result: {neon_tx_res}')

        return neon_tx_res

    def _build_cancel_tx_list(self) -> Generator[List[SolTx], None, None]:
        yield [self._build_cancel_tx()]


@alt_strategy
class ALTIterativeNeonTxStrategy(IterativeNeonTxStrategy):
    pass
