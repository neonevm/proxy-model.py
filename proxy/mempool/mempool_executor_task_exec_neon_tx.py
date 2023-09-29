import logging

from .mempool_api import MPTxExecRequest, MPTxExecResult, MPTxExecResultCode
from .mempool_executor_task_base import MPExecutorBaseTask
from .neon_tx_sender import NeonTxSendStrategyExecutor
from .neon_tx_sender_ctx import NeonTxSendCtx

from ..common_neon.config import Config
from ..common_neon.elf_params import ElfParams
from ..common_neon.errors import RescheduleError, NonceTooLowError, NonceTooHighError, BadResourceError, StuckTxError

from ..neon_core_api import NeonCoreApiClient


LOG = logging.getLogger(__name__)


class MPExecutorExecNeonTxTask(MPExecutorBaseTask):
    def __init__(self, config: Config, core_api_client: NeonCoreApiClient):
        super().__init__(config)
        self._core_api_client = core_api_client

    def execute_neon_tx(self, mp_tx_req: MPTxExecRequest) -> MPTxExecResult:
        neon_tx_exec_cfg = mp_tx_req.neon_tx_exec_cfg
        try:
            assert neon_tx_exec_cfg is not None
            self._execute_neon_tx(mp_tx_req)

        except NonceTooLowError:
            LOG.debug(f'Skip {mp_tx_req}, reason: nonce too low')

        except NonceTooHighError as exc:
            LOG.debug(f'Reschedule tx {mp_tx_req}, reason: nonce too high')
            neon_tx_exec_cfg.set_state_tx_cnt(exc.state_tx_cnt)
            return MPTxExecResult(MPTxExecResultCode.NonceTooHigh, neon_tx_exec_cfg)

        except BadResourceError as exc:
            LOG.debug(f'Reschedule tx {mp_tx_req.sig}, bad resource: {str(exc)}')
            return MPTxExecResult(MPTxExecResultCode.BadResource, neon_tx_exec_cfg)

        except RescheduleError as exc:
            LOG.debug(f'Reschedule tx {mp_tx_req.sig}, reason: {str(exc)}')
            return MPTxExecResult(MPTxExecResultCode.Reschedule, neon_tx_exec_cfg)

        except StuckTxError as exc:
            LOG.debug(f'Reschedule tx {mp_tx_req.sig }, reason: {str(exc)}')
            return MPTxExecResult(MPTxExecResultCode.StuckTx, exc)

        except BaseException as exc:
            LOG.error(f'Failed to execute tx {mp_tx_req.sig}', exc_info=exc)
            return MPTxExecResult(MPTxExecResultCode.Failed, exc)

        return MPTxExecResult(MPTxExecResultCode.Done, neon_tx_exec_cfg)

    def _execute_neon_tx(self, mp_tx_req: MPTxExecRequest):
        ElfParams().set_elf_param_dict(mp_tx_req.elf_param_dict)

        strategy_ctx = NeonTxSendCtx(self._config, self._solana, self._core_api_client, mp_tx_req)
        strategy_executor = NeonTxSendStrategyExecutor(strategy_ctx)
        strategy_executor.execute()
