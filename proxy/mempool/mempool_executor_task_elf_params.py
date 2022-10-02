from typing import Optional, Dict

from ..common_neon.elf_params import ElfParams

from ..mempool.mempool_executor_task_base import MPExecutorBaseTask


class MPExecutorElfParamsTask(MPExecutorBaseTask):
    def read_elf_param_dict(self) -> Optional[Dict[str, str]]:
        try:
            elf_params = ElfParams()
            elf_params.read_elf_param_dict_from_net()
            return elf_params.elf_param_dict
        except Exception as e:
            self._on_exception('Fail to read elf params', e)
            return None
