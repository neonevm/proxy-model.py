from ..common_neon.errors import BlockedAccountsError, NodeBehindError, SolanaUnavailableError, NonceTooLowError
from ..common_neon.errors import BadResourceError
from ..common_neon.elf_params import ElfParams

from ..mempool.mempool_api import MPTxExecRequest, MPTxExecResult, MPTxExecResultCode
from ..mempool.mempool_executor_task_base import MPExecutorBaseTask
from ..mempool.operator_resource_mng import OpResInfo
from ..mempool.neon_tx_sender_ctx import NeonTxSendCtx
from ..mempool.neon_tx_sender import NeonTxSendStrategyExecutor


class MPExecutorExecNeonTxTask(MPExecutorBaseTask):
    def execute_neon_tx(self, mp_tx_req: MPTxExecRequest):
        neon_tx_exec_cfg = mp_tx_req.neon_tx_exec_cfg
        try:
            assert neon_tx_exec_cfg is not None
            self.execute_neon_tx_impl(mp_tx_req)
        except BlockedAccountsError:
            self.debug(f"Failed to execute tx {mp_tx_req.sig}, got blocked accounts result")
            return MPTxExecResult(MPTxExecResultCode.BlockedAccount, neon_tx_exec_cfg)
        except NodeBehindError:
            self.debug(f"Failed to execute tx {mp_tx_req.sig}, got node behind error")
            return MPTxExecResult(MPTxExecResultCode.NodeBehind, neon_tx_exec_cfg)
        except SolanaUnavailableError:
            self.debug(f"Failed to execute tx {mp_tx_req.sig}, got solana unavailable error")
            return MPTxExecResult(MPTxExecResultCode.SolanaUnavailable, neon_tx_exec_cfg)
        except NonceTooLowError:
            self.debug(f"Failed to execute tx {mp_tx_req.sig}, got nonce too low error")
            return MPTxExecResult(MPTxExecResultCode.NonceTooLow, neon_tx_exec_cfg)
        except BadResourceError as e:
            self.debug(f"Failed to execute tx {mp_tx_req.sig}, got bad resource error {str(e)}")
            return MPTxExecResult(MPTxExecResultCode.BadResource, neon_tx_exec_cfg)
        except BaseException as exc:
            self.error(f'Failed to execute tx {mp_tx_req.sig}.', exc_info=exc)
            return MPTxExecResult(MPTxExecResultCode.Unspecified, neon_tx_exec_cfg)
        return MPTxExecResult(MPTxExecResultCode.Done, neon_tx_exec_cfg)

    def execute_neon_tx_impl(self, mp_tx_req: MPTxExecRequest):
        ElfParams().set_elf_param_dict(mp_tx_req.elf_param_dict)

        resource = OpResInfo.from_ident(mp_tx_req.resource_ident)

        neon_tx = mp_tx_req.neon_tx
        neon_tx_exec_cfg = mp_tx_req.neon_tx_exec_cfg
        strategy_ctx = NeonTxSendCtx(self._config, self._solana, resource, neon_tx, neon_tx_exec_cfg)
        strategy_executor = NeonTxSendStrategyExecutor(strategy_ctx)
        strategy_executor.execute()
