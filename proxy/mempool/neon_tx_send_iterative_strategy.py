from __future__ import annotations

from typing import List, cast
from logged_groups import logged_group
from dataclasses import dataclass

from ..common_neon.solana_transaction import SolTx, SolLegacyTx, SolWrappedTx, SolTxReceipt
from ..common_neon.solana_tx_list_sender import SolTxSendState
from ..common_neon.errors import NoMoreRetriesError
from ..common_neon.utils import NeonTxResultInfo

from ..mempool.neon_tx_send_base_strategy import BaseNeonTxStrategy
from ..mempool.neon_tx_send_simple_strategy import SimpleNeonTxSender
from ..mempool.neon_tx_send_strategy_base_stages import alt_strategy
from ..mempool.neon_tx_sender_ctx import NeonTxSendCtx


@dataclass
class SolIterativeTx(SolWrappedTx):
    evm_step_cnt: int


class IterativeNeonTxSender(SimpleNeonTxSender):
    def __init__(self, strategy: IterativeNeonTxStrategy, *args, **kwargs):
        super().__init__(strategy, *args, **kwargs)
        self._is_canceled = False

    def _decode_neon_tx_result(self, tx: SolTx, tx_receipt: SolTxReceipt) -> None:
        if self._neon_tx_res.is_valid():
            return
        elif self._is_canceled:
            # Transaction with cancel is confirmed
            self._neon_tx_res.fill_result(status="0x0", gas_used='0x0', return_value='')
            self.debug(f'Got Neon tx cancel: {self._neon_tx_res}')
        else:
            super()._decode_neon_tx_result(tx, tx_receipt)

    def _convert_state_to_tx_list(self, tx_status: SolTxSendState.Status,
                                  tx_state_list: List[SolTxSendState]) -> List[SolTx]:
        if self._neon_tx_res.is_valid():
            return []

        try:
            if tx_status == SolTxSendState.Status.BudgetExceededError:
                return self._decrease_evm_step_cnt(tx_state_list)
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
            return self._strategy.build_tx_list(0, 1)

        return tx_list

    def _cancel(self, e: Exception) -> List[SolTx]:
        if (not self._has_good_receipt_list()) or self._is_canceled:
            raise e

        self.debug(f'Cancel the transaction')
        self.clear()
        self._is_canceled = True
        return [SolWrappedTx(name='CancelWithHash', tx=self._strategy.build_cancel_tx())]

    def _decrease_evm_step_cnt(self, tx_state_list: List[SolTxSendState]) -> List[SolTx]:
        if not self._strategy.decrease_evm_step_cnt():
            raise NoMoreRetriesError()

        total_evm_step_cnt = sum([cast(SolIterativeTx, tx_state.tx).evm_step_cnt for tx_state in tx_state_list])
        return self._strategy.build_tx_list(total_evm_step_cnt, 0)


@logged_group("neon.MemPool")
class IterativeNeonTxStrategy(BaseNeonTxStrategy):
    name = 'TransactionStepFromInstruction'

    def __init__(self, ctx: NeonTxSendCtx) -> None:
        super().__init__(ctx)
        self._uniq_idx = 0
        self._evm_step_cnt = self._start_evm_step_cnt

    def _validate(self) -> bool:
        return (
            self._validate_notdeploy_tx() and
            self._validate_tx_has_chainid()
        )

    def build_cancel_tx(self) -> SolLegacyTx:
        return self._build_cancel_tx()

    def decrease_evm_step_cnt(self) -> bool:
        if self._evm_step_cnt == 10:
            return False

        prev_evm_step_cnt = self._evm_step_cnt
        if self._evm_step_cnt > 170:
            self._evm_step_cnt -= 150
        else:
            self._evm_step_cnt = 10
        self.debug(f'Decrease EVM steps from {prev_evm_step_cnt} to {self._evm_step_cnt}')

        if (self._evm_step_cnt < self._base_evm_step_cnt) and (self._bpf_cycle_cnt is None):
            self._bpf_cycle_cnt = 1_400_000
            self.debug(f'Increase BPF cycles to {self._bpf_cycle_cnt}.')

        return True

    def _build_tx(self) -> SolLegacyTx:
        self._uniq_idx += 1
        return BaseNeonTxStrategy._build_tx(self).add(
            self._ctx.ix_builder.make_tx_step_from_data_ix(self._evm_step_cnt, self._uniq_idx)
        )

    def build_tx_list(self, total_evm_step_cnt: int, add_iter_cnt: int) -> List[SolTx]:
        def build_tx(step_cnt: int):
            return SolIterativeTx(name=self.name, tx=self._build_tx(), evm_step_cnt=step_cnt)

        tx_list: List[SolTx] = []
        save_evm_step_cnt = total_evm_step_cnt

        for _ in range(add_iter_cnt):
            tx_list.append(build_tx(self._evm_step_cnt))

        while total_evm_step_cnt > 0:
            evm_step_cnt = self._evm_step_cnt if total_evm_step_cnt > self._evm_step_cnt else total_evm_step_cnt
            total_evm_step_cnt -= evm_step_cnt

            tx_list.append(build_tx(evm_step_cnt))

        self.debug(f'Total iterations {len(tx_list)} for {save_evm_step_cnt} ({self._evm_step_cnt}) EVM steps')
        return tx_list

    def execute(self) -> NeonTxResultInfo:
        assert self.is_valid()

        emulated_step_cnt = max(self._ctx.emulated_evm_step_cnt, self._start_evm_step_cnt)
        tx_list = self.build_tx_list(emulated_step_cnt, self._ctx.neon_tx_exec_cfg.resize_iter_cnt)
        tx_sender = IterativeNeonTxSender(self, self._ctx.solana, self._ctx.signer)
        tx_sender.send(tx_list)
        if not tx_sender.neon_tx_res.is_valid():
            raise NoMoreRetriesError()
        return tx_sender.neon_tx_res


@alt_strategy
class ALTIterativeNeonTxStrategy(IterativeNeonTxStrategy):
    pass
