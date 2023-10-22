import abc

from ..common_neon.constants import ONE_BLOCK_SEC

from .executor_mng import MPExecutorMng
from .mempool_api import MPGetEVMConfigRequest, MPEVMConfigResult
from .mempool_periodic_task import MPPeriodicTaskLoop

from ..common_neon.evm_config import EVMConfig


class IEVMConfigUser(abc.ABC):
    @abc.abstractmethod
    def on_evm_config(self, evm_config: EVMConfig) -> None: pass


class MPEVMConfigTaskLoop(MPPeriodicTaskLoop[MPGetEVMConfigRequest, MPEVMConfigResult]):
    _default_sleep_sec = ONE_BLOCK_SEC * 16

    def __init__(self, executor_mng: MPExecutorMng, user: IEVMConfigUser) -> None:
        super().__init__(name='evm-config', sleep_sec=self._default_sleep_sec, executor_mng=executor_mng)
        self._user = user

    def _submit_request(self) -> None:
        req_id = self._generate_req_id()
        mp_req = MPGetEVMConfigRequest(req_id=req_id, evm_config_data=EVMConfig().evm_config_data)
        self._submit_request_to_executor(mp_req)

    def _process_error(self, _: MPGetEVMConfigRequest) -> None:
        pass

    async def _process_result(self, _: MPGetEVMConfigRequest, mp_res: MPEVMConfigResult) -> None:
        evm_config = EVMConfig()
        if mp_res.last_deployed_slot > evm_config.last_deployed_slot:
            evm_config.set_evm_config(mp_res)
            self._user.on_evm_config(evm_config)
