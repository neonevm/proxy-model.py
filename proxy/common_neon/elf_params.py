from __future__ import annotations

from typing import Optional, Dict, Any

from logged_groups import logged_group
from singleton_decorator import singleton

from solana.publickey import PublicKey

from .environment_utils import neon_cli


@logged_group("Neon.Proxy")
@singleton
class ElfParams:
    def __init__(self):
        self._elf_param_dict: Dict[str, any] = {}
        self.read_elf_param_from_net()

    @property
    def collateral_pool_base(self) -> Optional[str]:
        return self._elf_param_dict.get("NEON_POOL_BASE")

    @property
    def neon_heap_frame(self) -> int:
        return int(self._elf_param_dict.get("NEON_HEAP_FRAME"))

    @property
    def neon_compute_units(self) -> int:
        return int(self._elf_param_dict.get("NEON_COMPUTE_UNITS"))

    @property
    def neon_additional_fee(self):
        return int(self._elf_param_dict.get("NEON_ADDITIONAL_FEE"))

    @property
    def neon_token_mint(self) -> PublicKey:
        return PublicKey(self._elf_param_dict.get("NEON_TOKEN_MINT"))

    @property
    def chain_id(self) -> int:
        return int(self._elf_param_dict.get('NEON_CHAIN_ID'))

    @property
    def holder_msg_size(self) -> int:
        return int(self._elf_param_dict.get("NEON_HOLDER_MSG_SIZE"))

    @property
    def neon_evm_version(self) -> Optional[str]:
        return self._elf_param_dict.get("NEON_PKG_VERSION")

    @property
    def neon_evm_revision(self) -> Optional[str]:
        return self._elf_param_dict.get('NEON_REVISION')

    @property
    def neon_gas_limit_multiplier_no_chainid(self) -> int:
        return int(self._elf_param_dict.get('NEON_GAS_LIMIT_MULTIPLIER_NO_CHAINID'))

    @property
    def neon_minimal_client_allowance_balance(self) -> int:
        return int(self._elf_param_dict.get("NEON_MINIMAL_CLIENT_ALLOWANCE_BALANCE", 0))

    @property
    def neon_minimal_contract_allowance_balance(self) -> int:
        return int(self._elf_param_dict.get("NEON_MINIMAL_CONTRACT_ALLOWANCE_BALANCE", 0))

    @property
    def allowance_token_addr(self) -> str:
        return self._elf_param_dict.get("NEON_PERMISSION_ALLOWANCE_TOKEN", '')

    @property
    def denial_token_addr(self) -> str:
        return self._elf_param_dict.get("NEON_PERMISSION_DENIAL_TOKEN", '')

    def is_evm_compatible(self, proxy_version: str) -> bool:
        evm_version = None
        try:
            evm_version = self.neon_evm_version
            major_evm_version, minor_evm_version, _ = evm_version.split('.')
            major_proxy_version, minor_proxy_version, _ = proxy_version.split('.')
            return (major_evm_version == major_proxy_version) and (minor_evm_version == minor_proxy_version)
        except Exception as e:
            self.error(f"can't compare evm version {evm_version} with proxy version {proxy_version}: {str(e)}")
            return False

    @property
    def elf_param_dict(self) -> Dict[str: Any]:
        return self._elf_param_dict

    def read_elf_param_dict_from_net(self) -> None:
        self.debug("Read ELF params")
        try:
            elf_param_dict: Dict[str, Any] = {}
            for param in neon_cli().call("neon-elf-params").splitlines():
                if param.startswith('NEON_') and '=' in param:
                    v = param.split('=')
                    elf_param_dict.setdefault(v[0], v[1])
                    self.debug(f"ELF param: {v[0]}: {v[1]}")
            self.set_elf_param_dict(elf_param_dict)
        except Exception as e:
            self.error(f"can't read ELF params from network: {str(e)}")

    def set_elf_param_dict(self, elf_param_dict: Dict[str, Any]) -> None:
        self._elf_param_dict = elf_param_dict
