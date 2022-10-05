from logged_groups import logged_group

from ..common_neon.emulator_interactor import call_trx_emulated
from ..common_neon.errors import NonceTooLowError, BudgetExceededError, NoMoreRetriesError
from ..common_neon.utils import NeonTxResultInfo
from ..common_neon.data import NeonEmulatedResult
from ..common_neon.address import EthereumAddress

from ..mempool.neon_tx_sender_ctx import NeonTxSendCtx
from ..mempool.neon_tx_send_base_strategy import BaseNeonTxStrategy
from ..mempool.neon_tx_send_simple_strategy import SimpleNeonTxStrategy, ALTSimpleNeonTxStrategy
from ..mempool.neon_tx_send_iterative_strategy import IterativeNeonTxStrategy, ALTIterativeNeonTxStrategy
from ..mempool.neon_tx_send_holder_strategy import HolderNeonTxStrategy, ALTHolderNeonTxStrategy
from ..mempool.neon_tx_send_nochainid_strategy import NoChainIdNeonTxStrategy, ALTNoChainIdNeonTxStrategy


@logged_group("neon.MemPool")
class NeonTxSendStrategyExecutor:
    _strategy_list = [
        SimpleNeonTxStrategy, ALTSimpleNeonTxStrategy,
        IterativeNeonTxStrategy, ALTIterativeNeonTxStrategy,
        HolderNeonTxStrategy, ALTHolderNeonTxStrategy,
        NoChainIdNeonTxStrategy, ALTNoChainIdNeonTxStrategy
    ]

    def __init__(self, ctx: NeonTxSendCtx):
        self._ctx = ctx

    def execute(self) -> NeonTxResultInfo:
        self._validate_nonce()
        return self._execute()

    def _init_state_tx_cnt(self) -> None:
        neon_account_info = self._ctx.solana.get_neon_account_info(EthereumAddress(self._ctx.sender))
        state_tx_cnt = neon_account_info.tx_count if neon_account_info is not None else 0
        self._ctx.set_state_tx_cnt(state_tx_cnt)

    def _emulate_neon_tx(self) -> None:
        emulated_result: NeonEmulatedResult = call_trx_emulated(self._ctx.neon_tx)
        self._ctx.set_emulated_result(emulated_result)
        self._validate_nonce()

    def _validate_nonce(self) -> None:
        self._init_state_tx_cnt()
        if self._ctx.state_tx_cnt > self._ctx.neon_tx.nonce:
            raise NonceTooLowError()

    def _execute(self) -> NeonTxResultInfo:
        for Strategy in self._strategy_list:
            try:
                strategy: BaseNeonTxStrategy = Strategy(self._ctx)
                if not strategy.validate():
                    self.debug(f'Skip strategy {Strategy.name}: {strategy.validation_error_msg}')
                    continue
                self.debug(f'Use strategy {Strategy.name}')

                strategy.prep_before_emulate()
                for i in range(self._ctx.config.retry_on_fail):
                    self._emulate_neon_tx()

                    if not strategy.validate():
                        self.debug(f'Skip strategy {Strategy.name}: {strategy.validation_error_msg}')
                        continue

                    return strategy.execute()
                raise NoMoreRetriesError()

            except (BudgetExceededError,):
                continue
            except (Exception,):
                raise
            finally:
                self._init_state_tx_cnt()

        raise RuntimeError('transaction is too big for execution')
