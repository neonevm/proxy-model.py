import logging

from ..common_neon.elf_params import ElfParams
from ..common_neon.errors import RescheduleError, NonceTooLowError, NonceTooHighError, BadResourceError

from ..mempool.mempool_api import MPTxExecRequest, MPTxExecResult, MPTxExecResultCode
from ..mempool.mempool_executor_task_base import MPExecutorBaseTask
from ..mempool.neon_tx_sender import NeonTxSendStrategyExecutor
from ..mempool.neon_tx_sender_ctx import NeonTxSendCtx
from ..mempool.operator_resource_mng import OpResInfo


LOG = logging.getLogger(__name__)


class MPExecutorExecNeonTxTask(MPExecutorBaseTask):
    def execute_neon_tx(self, mp_tx_req: MPTxExecRequest) -> MPTxExecResult:
        neon_tx_exec_cfg = mp_tx_req.neon_tx_exec_cfg
        try:
            assert neon_tx_exec_cfg is not None
            self.execute_neon_tx_impl(mp_tx_req)

        except NonceTooLowError:
            LOG.debug(f'Skip {mp_tx_req}, reason: nonce too low')

        except NonceTooHighError:
            LOG.debug(f'Reschedule tx {mp_tx_req}, reason: nonce too high')
            return MPTxExecResult(MPTxExecResultCode.NonceTooHigh, neon_tx_exec_cfg)

        except BadResourceError as exc:
            LOG.debug(f'Reschedule tx {mp_tx_req.sig}, bad resource: {str(exc)}')
            return MPTxExecResult(MPTxExecResultCode.BadResource, neon_tx_exec_cfg)

        except RescheduleError as exc:
            LOG.debug(f'Reschedule tx {mp_tx_req.sig}, reason: {str(exc)}')
            return MPTxExecResult(MPTxExecResultCode.Reschedule, neon_tx_exec_cfg)

        except BaseException as exc:
            LOG.error(f'Failed to execute tx {mp_tx_req.sig}', exc_info=exc)
            return MPTxExecResult(MPTxExecResultCode.Failed, exc)

        return MPTxExecResult(MPTxExecResultCode.Done, neon_tx_exec_cfg)

    def execute_neon_tx_impl(self, mp_tx_req: MPTxExecRequest):
        ElfParams().set_elf_param_dict(mp_tx_req.elf_param_dict)

        resource = OpResInfo.from_ident(mp_tx_req.res_ident)

        neon_tx = mp_tx_req.neon_tx
        neon_tx_exec_cfg = mp_tx_req.neon_tx_exec_cfg
        strategy_ctx = NeonTxSendCtx(self._config, self._solana, resource, neon_tx, neon_tx_exec_cfg)
        strategy_executor = NeonTxSendStrategyExecutor(strategy_ctx)
        strategy_executor.execute()
