import logging

from ..common_neon.errors import (
    NonceTooLowError, NonceTooHighError, WrongStrategyError, RescheduleError, BigTxError,
    NoMoreRetriesError, TxAccountCntTooBig
)

from ..common_neon.neon_tx_result_info import NeonTxResultInfo

from .neon_tx_send_base_strategy import BaseNeonTxStrategy
from .neon_tx_send_holder_strategy import HolderNeonTxStrategy, ALTHolderNeonTxStrategy
from .neon_tx_send_simple_holder_strategy import SimpleHolderNeonTxStrategy, ALTSimpleHolderNeonTxStrategy
from .neon_tx_send_iterative_strategy import IterativeNeonTxStrategy, ALTIterativeNeonTxStrategy
from .neon_tx_send_nochainid_strategy import NoChainIdNeonTxStrategy, ALTNoChainIdNeonTxStrategy
from .neon_tx_send_simple_strategy import SimpleNeonTxStrategy, ALTSimpleNeonTxStrategy
from .neon_tx_sender_ctx import NeonTxSendCtx


LOG = logging.getLogger(__name__)


class NeonTxSendStrategyExecutor:
    _strategy_list = [
        SimpleNeonTxStrategy, ALTSimpleNeonTxStrategy,
        IterativeNeonTxStrategy, ALTIterativeNeonTxStrategy,
        SimpleHolderNeonTxStrategy, ALTSimpleHolderNeonTxStrategy,
        HolderNeonTxStrategy, ALTHolderNeonTxStrategy,
        NoChainIdNeonTxStrategy, ALTNoChainIdNeonTxStrategy
    ]

    def __init__(self, ctx: NeonTxSendCtx):
        self._ctx = ctx

    def execute(self) -> NeonTxResultInfo:
        self._validate_nonce()

        start_idx = self._ctx.strategy_idx
        end_idx = len(self._strategy_list)
        try:
            return self._iter_strategy_list(start_idx, end_idx)
        finally:
            self._init_state_tx_cnt()

    def _iter_strategy_list(self, start: int, end: int) -> NeonTxResultInfo:
        for strategy_idx in range(start, end):
            strategy = self._strategy_list[strategy_idx](self._ctx)
            try:
                if not strategy.validate():
                    LOG.debug(f'Skip strategy {strategy.name}: {strategy.validation_error_msg}')
                    continue

                return self._execute(strategy_idx, strategy)

            except (RescheduleError, NonceTooLowError):
                raise

            except WrongStrategyError:
                if not self._ctx.has_good_sol_tx_receipt():
                    continue
                self._cancel(strategy)
                raise

            except BaseException as exc:
                LOG.warning('Fail on execute tx', exc_info=exc)
                self._cancel(strategy)
                raise

        raise BigTxError()

    def _execute(self, strategy_idx: int, strategy: BaseNeonTxStrategy) -> NeonTxResultInfo:
        LOG.debug(f'Use strategy {strategy.name}')

        strategy.complete_init()
        self._ctx.set_strategy_idx(strategy_idx)

        # Try `retry_on_fail` times to prepare Neon tx for execution
        retry_on_fail = self._ctx.config.retry_on_fail
        for retry in range(retry_on_fail):
            has_changes = strategy.prep_before_emulate()
            if has_changes or (retry == 0):
                # no re-emulation for Neon tx with started state
                if not self._ctx.has_good_sol_tx_receipt():
                    self._emulate_neon_tx()
                strategy.update_after_emulate()

            # Preparation made changes in the Solana state -> repeat preparation and re-emulation
            if has_changes:
                continue

            # Neon tx is prepared for execution
            try:
                return strategy.execute()

            finally:
                if strategy.has_good_sol_tx_receipt():
                    self._ctx.mark_good_sol_tx_receipt()

        # Can't prepare Neon tx for execution in `retry_on_fail` attempts
        raise NoMoreRetriesError()

    @staticmethod
    def _cancel(strategy: BaseNeonTxStrategy) -> None:
        try:
            strategy.cancel()

        except RescheduleError:
            raise

        except BaseException as exc:
            LOG.error('Failed to cancel tx', exc_info=exc)

    def _init_state_tx_cnt(self) -> None:
        state_tx_cnt = self._ctx.core_api_client.get_state_tx_cnt(self._ctx.sender_address)
        if self._ctx.has_good_sol_tx_receipt():
            state_tx_cnt = max(state_tx_cnt, self._ctx.neon_tx_info.nonce)
        self._ctx.set_state_tx_cnt(state_tx_cnt)

    def _emulate_neon_tx(self) -> None:
        if self._ctx.is_stuck_tx():
            return

        had_emulator_result = self._ctx.has_emulator_result()
        self._ctx.emulate()
        if not had_emulator_result:
            self._validate_tx_acct_amount()
        self._validate_nonce()

    def _validate_tx_acct_amount(self) -> None:
        # 6 is the base number of account in Neon Instruction. see NeonIxBuilder
        acct_cnt = self._ctx.len_account_list + 5
        if acct_cnt > self._ctx.config.max_tx_account_cnt:
            raise TxAccountCntTooBig(acct_cnt, self._ctx.config.max_tx_account_cnt)

    def _validate_nonce(self) -> None:
        self._init_state_tx_cnt()
        if self._ctx.state_tx_cnt == self._ctx.neon_tx_info.nonce:
            return

        if self._ctx.state_tx_cnt < self._ctx.neon_tx_info.nonce:
            raise NonceTooHighError(self._ctx.state_tx_cnt)
        raise NonceTooLowError(self._ctx.neon_tx_info.addr, self._ctx.neon_tx_info.nonce, self._ctx.state_tx_cnt)
