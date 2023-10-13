import logging
from typing import Optional

from .mempool_api import MPGetEVMConfigRequest, MPEVMConfigResult
from .mempool_executor_task_base import MPExecutorBaseTask

from ..common_neon.constants import EVM_PROGRAM_ID_STR
from ..common_neon.solana_tx import SolPubKey

from ..neon_core_api.neon_layouts import BPFLoader2ProgramInfo, BPFLoader2ExecutableInfo, EVMConfigInfo


LOG = logging.getLogger(__name__)


class MPExecutorEVMConfigTask(MPExecutorBaseTask):
    def get_evm_config(self, mp_req: MPGetEVMConfigRequest) -> Optional[MPEVMConfigResult]:
        try:
            return self._get_evm_config(mp_req.evm_config_data)
        except BaseException as exc:
            LOG.error('Failed to get EVM config', exc_info=exc)
            return None

    def _get_evm_config(self, src_cfg_data: EVMConfigInfo) -> EVMConfigInfo:
        account_info = self._solana.get_account_info(EVM_PROGRAM_ID_STR)
        program_info = BPFLoader2ProgramInfo.from_data(account_info.data)
        if program_info.executable_addr == SolPubKey.default():
            return EVMConfigInfo.init_empty()

        min_size = BPFLoader2ExecutableInfo.minimum_size
        account_info = self._solana.get_account_info(program_info.executable_addr, min_size)
        exec_info = BPFLoader2ExecutableInfo.from_data(account_info.data)
        if exec_info.deployed_slot <= src_cfg_data.last_deployed_slot:
            return EVMConfigInfo.init_empty()

        LOG.debug(f'Get EVM config on the slot {exec_info.deployed_slot}')
        evm_cfg_data = self._core_api_client.get_evm_config(exec_info.deployed_slot)
        src_param_dict = {
            key: value
            for key, value in src_cfg_data.evm_param_list
        }
        for key, value in evm_cfg_data.evm_param_list:
            if key not in src_param_dict:
                LOG.debug(f'Get EVM param {key}={value}')

        return evm_cfg_data
