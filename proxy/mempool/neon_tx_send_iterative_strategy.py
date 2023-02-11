from __future__ import annotations

import logging
from typing import List

from ..common_neon.errors import CUBudgetExceededError, NoMoreRetriesError
from ..common_neon.solana_tx import SolTxReceipt, SolTx
from ..common_neon.solana_tx_legacy import SolLegacyTx
from ..common_neon.solana_tx_list_sender import SolTxSendState
from ..common_neon.utils import NeonTxResultInfo

from ..mempool.neon_tx_send_base_strategy import BaseNeonTxStrategy
from ..mempool.neon_tx_send_simple_strategy import SimpleNeonTxSender
from ..mempool.neon_tx_send_strategy_base_stages import alt_strategy
from ..mempool.neon_tx_sender_ctx import NeonTxSendCtx


LOG = logging.getLogger(__name__)


class IterativeNeonTxSender(SimpleNeonTxSender):
    def __init__(self, strategy: IterativeNeonTxStrategy, *args, **kwargs):
        super().__init__(strategy, *args, **kwargs)
        self._strategy = strategy
        self._is_canceled = False

    def _decode_neon_tx_result(self, tx: SolTx, tx_receipt: SolTxReceipt) -> None:
        if self._neon_tx_res.is_valid():
            return
        elif self._is_canceled:
            # Transaction with cancel is confirmed
            self._neon_tx_res.set_result(status=0, gas_used=0)
            LOG.debug(f'Got Neon tx cancel: {self._neon_tx_res}')
        else:
            super()._decode_neon_tx_result(tx, tx_receipt)

    def _convert_state_to_tx_list(self, tx_status: SolTxSendState.Status,
                                  tx_state_list: List[SolTxSendState]) -> List[SolTx]:
        if self._neon_tx_res.is_valid():
            return list()

        try:
            if tx_status == SolTxSendState.Status.CUBudgetExceededError:
                raise CUBudgetExceededError()
            elif tx_status == SolTxSendState.Status.BlockedAccountError:
                if self._has_good_receipt_list():
                    return self._get_tx_list_from_state(tx_state_list)
            return super()._convert_state_to_tx_list(tx_status, tx_state_list)
        except Exception as e:
            return self._cancel(e)

    def _get_tx_list_for_send(self) -> List[SolTx]:
        if self._retry_idx >= self._config.retry_on_fail:
            return self._cancel(NoMoreRetriesError())

        tx_list = super()._get_tx_list_for_send()
        if self._neon_tx_res.is_valid() or self._is_canceled or self._has_waiting_tx_list():
            pass
        elif self._has_good_receipt_list() and (len(tx_list) == 0):
            # send additional iteration to complete tx
            LOG.debug('No receipt -> execute additional iteration')
            return self._strategy.build_tx_list(0, 1)

        return tx_list

    def _cancel(self, e: Exception) -> List[SolTx]:
        if (not self._has_good_receipt_list()) or self._is_canceled:
            raise e

        LOG.debug('Cancel the transaction')
        self.clear()
        self._is_canceled = True
        return [self._strategy.build_cancel_tx()]


class IterativeNeonTxStrategy(BaseNeonTxStrategy):
    name = 'TxStepFromData'

    def __init__(self, ctx: NeonTxSendCtx) -> None:
        super().__init__(ctx)
        self._uniq_idx = 0

    def _validate(self) -> bool:
        return self._validate_tx_has_chainid()

    def build_cancel_tx(self) -> SolLegacyTx:
        return self._build_cancel_tx()

    def _build_tx(self) -> SolLegacyTx:
        self._uniq_idx += 1
        return self._build_cu_tx(self._ctx.ix_builder.make_tx_step_from_data_ix(self._evm_step_cnt, self._uniq_idx))

    def build_tx_list(self, total_evm_step_cnt: int, add_iter_cnt: int) -> List[SolTx]:
        def build_tx(step_cnt: int) -> SolTx:
            tx = self._build_tx()
            setattr(tx, 'evm_step_cnt', step_cnt)
            return tx

        tx_list: List[SolTx] = []
        save_evm_step_cnt = total_evm_step_cnt

        for _ in range(add_iter_cnt):
            tx_list.append(build_tx(self._evm_step_cnt))

        while total_evm_step_cnt > 0:
            evm_step_cnt = self._evm_step_cnt if total_evm_step_cnt > self._evm_step_cnt else total_evm_step_cnt
            total_evm_step_cnt -= evm_step_cnt

            tx_list.append(build_tx(evm_step_cnt))

        LOG.debug(f'Total iterations {len(tx_list)} for {save_evm_step_cnt} ({self._evm_step_cnt}) EVM steps')
        return tx_list

    def execute(self) -> NeonTxResultInfo:
        assert self.is_valid()

        LOG.debug(
            f'Total EVM steps {self._ctx.emulated_evm_step_cnt}, '
            f'total resize iterations {self._ctx.neon_tx_exec_cfg.resize_iter_cnt}'
        )

        emulated_step_cnt = max(self._ctx.emulated_evm_step_cnt, self._evm_step_cnt)
        additional_iter_cnt = self._ctx.neon_tx_exec_cfg.resize_iter_cnt
        additional_iter_cnt += 2  # begin + finalization
        tx_list = self.build_tx_list(emulated_step_cnt, additional_iter_cnt)
        tx_sender = IterativeNeonTxSender(self, self._ctx.solana, self._ctx.signer)
        tx_sender.send(tx_list)
        if not tx_sender.neon_tx_res.is_valid():
            raise NoMoreRetriesError()
        return tx_sender.neon_tx_res


@alt_strategy
class ALTIterativeNeonTxStrategy(IterativeNeonTxStrategy):
    pass
