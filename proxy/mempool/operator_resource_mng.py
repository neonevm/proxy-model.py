from __future__ import annotations

import math
import traceback
from datetime import datetime
from typing import Optional, List, Tuple, Dict

from logged_groups import logged_group
from solana.account import Account as SolanaAccount
from solana.publickey import PublicKey

from ..common_neon.config import Config
from ..common_neon.address import EthereumAddress, ether2program, permAccountSeed, accountWithSeed
from ..common_neon.constants import ACTIVE_HOLDER_TAG, FINALIZED_HOLDER_TAG, HOLDER_TAG
from ..common_neon.solana_tx_list_sender import SolTxListInfo, SolTxListSender
from ..common_neon.environment_utils import get_solana_accounts
from ..common_neon.cancel_transaction_executor import CancelTxExecutor
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.errors import BadResourceError

from .neon_tx_stages import NeonTxStage
from .neon_tx_stages import NeonCreateAccountTxStage, NeonCreateHolderAccountStage, NeonDeleteHolderAccountStage


@logged_group("neon.MemPool")
class OperatorResourceInfo:
    def __init__(self, signer: SolanaAccount, resource_id: int):
        self._signer = signer
        self._resource_id = resource_id

        self._holder_seed = permAccountSeed(b'holder-', resource_id)
        self._holder = accountWithSeed(self.public_key, self._holder_seed)

        self._ether = EthereumAddress.from_private_key(self.secret_key)

    @staticmethod
    def from_ident(ident: str) -> OperatorResourceInfo:
        key, rid = ident.split(':')
        return OperatorResourceInfo(signer=SolanaAccount(bytes.fromhex(key)), resource_id=int(rid, 16))

    def __str__(self) -> str:
        return f'{str(self.public_key)}:{self._resource_id}'

    @property
    def holder(self) -> PublicKey:
        return self._holder

    @property
    def holder_seed(self) -> bytes:
        return self._holder_seed

    @property
    def ether(self) -> EthereumAddress:
        return self._ether

    @property
    def signer(self) -> SolanaAccount:
        return self._signer

    @property
    def public_key(self) -> PublicKey:
        return self._signer.public_key()

    @property
    def secret_key(self) -> bytes:
        return self._signer.secret_key()

    @property
    def resource_id(self) -> int:
        return self._resource_id


@logged_group("neon.MemPool")
class OperatorResourceInitializer:
    def __init__(self, config: Config, solana: SolanaInteractor):
        self._config = config
        self._solana = solana

    def init_resource(self, resource: OperatorResourceInfo):
        self.debug(f'Rechecking of accounts for resource {resource}')

        try:
            self._validate_operator_balance(resource)

            builder = NeonIxBuilder(resource.public_key)
            self._create_holder_account(builder, resource)
            self._create_ether_account(builder, resource)
        except BadResourceError:
            raise
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f"Fail to init accounts for resource {resource}. Error ({err}). Traceback: {err_tb}")
            raise BadResourceError(err)

    def _validate_operator_balance(self, resource: OperatorResourceInfo) -> None:
        # Validate operator's account has enough SOLs
        sol_balance = self._solana.get_sol_balance(resource.public_key)
        min_operator_balance_to_err = self._config.get_min_operator_balance_to_err()
        if sol_balance <= min_operator_balance_to_err:
            self.error(
                f'Operator account {resource} has NOT enough SOLs; balance = {sol_balance}; ' +
                f'min_operator_balance_to_err = {min_operator_balance_to_err}'
            )
            raise BadResourceError(f'Not enough SOLs on the resource {resource}')

        min_operator_balance_to_warn = self._config.get_min_operator_balance_to_warn()
        if sol_balance <= min_operator_balance_to_warn:
            self.warning(
                f'Operator account {resource} SOLs are running out; balance = {sol_balance}; ' +
                f'min_operator_balance_to_warn = {min_operator_balance_to_warn}; ' +
                f'min_operator_balance_to_err = {min_operator_balance_to_err}; '
            )

    def _execute_stage(self, stage: NeonTxStage, resource: OperatorResourceInfo) -> None:
        stage.build()
        tx_list = SolTxListInfo(name_list=[stage.NAME], tx_list=[stage.tx])
        tx_sender = SolTxListSender(self._solana, resource.signer)
        tx_sender.send(tx_list)

    def _create_ether_account(self, builder: NeonIxBuilder, resource: OperatorResourceInfo):
        solana_address = ether2program(resource.ether)[0]

        account_info = self._solana.get_account_info(solana_address)
        if account_info is not None:
            self.debug(f"Use ether account {str(solana_address)}({str(resource.ether)}) for resource {resource}")
            return []

        self.debug(f"Create ether account {str(solana_address)}({str(resource.ether)}) for resource {resource}")
        stage = NeonCreateAccountTxStage(builder, {"address": resource.ether})
        stage.set_balance(self._solana.get_multiple_rent_exempt_balances_for_size([stage.size])[0])
        self._execute_stage(stage, resource)

    def _create_holder_account(self, builder: NeonIxBuilder, resource: OperatorResourceInfo) -> None:
        holder_address = str(resource.holder)
        holder_seed = resource.holder_seed
        holder_info = self._solana.get_account_info(resource.holder)
        size = self._config.get_holder_size()
        balance = self._solana.get_multiple_rent_exempt_balances_for_size([size])[0]

        if holder_info is None:
            self.debug(f"Create account {holder_address} for resource {resource}")
            self._execute_stage(NeonCreateHolderAccountStage(builder, holder_seed, size, balance), resource)
        elif holder_info.lamports < balance:
            self.debug(f"Resize account {holder_address} for resource {resource}")
            self._execute_stage(NeonDeleteHolderAccountStage(builder, resource.holder_seed), resource)
            self._execute_stage(NeonCreateHolderAccountStage(builder, holder_seed, size, balance), resource)
        elif holder_info.owner != self._config.get_evm_loader_id():
            raise BadResourceError(f'Wrong owner of {str(holder_info.owner)} for resource {resource}')
        elif holder_info.tag == ACTIVE_HOLDER_TAG:
            self._unlock_holder_account(resource)
        elif holder_info.tag not in (FINALIZED_HOLDER_TAG, HOLDER_TAG):
            raise BadResourceError(f'Holder {holder_address} for resource {resource} has bad tag {holder_info.tag}')
        else:
            self.debug(f"Use account {str(holder_info.owner)} for resource {resource}")

    def _unlock_holder_account(self, resource: OperatorResourceInfo) -> None:
        self.debug(f"Cancel transaction in {str(resource.holder)} for resource {resource}")
        holder_info = self._solana.get_holder_account_info(resource.holder)
        cancel_tx_executor = CancelTxExecutor(self._solana, resource.signer)
        cancel_tx_executor.add_blocked_holder_account(holder_info)
        cancel_tx_executor.execute_tx_list()


class OperatorResourceIdent:
    def __init__(self, signer: SolanaAccount, resource_id: int):
        self._signer = signer
        self._resource_id = resource_id

        self._last_used_time = 0
        self._used_cnt = 0

    @property
    def ident(self) -> str:
        return f'{self._signer.secret_key().hex()}:{hex(self._resource_id)}'

    @property
    def last_used_time(self) -> int:
        return self._last_used_time

    @property
    def used_cnt(self) -> int:
        return self._used_cnt

    def set_last_used_time(self, value: int) -> None:
        self._used_cnt += 1
        self._last_used_time = value

    def reset_used_cnt(self) -> None:
        self._used_cnt = 0


@logged_group("neon.MemPool")
class OperatorResourceMng:
    def __init__(self, config: Config):
        self._free_resource_list: List[OperatorResourceIdent] = []
        self._used_resource_dict: Dict[str, OperatorResourceIdent] = {}
        self._disabled_resource_list: List[OperatorResourceIdent] = []
        self._config = config
        self._resource_cnt = 0
        self._init_resource_list()

    def _init_resource_list(self):
        signer_list: List[SolanaAccount] = self._get_solana_accounts()
        for resource_id in range(self._config.get_perm_account_limit()):
            for signer in signer_list:
                info = OperatorResourceIdent(signer=signer, resource_id=resource_id)
                self._disabled_resource_list.append(info)
        self._resource_cnt = len(self._disabled_resource_list)
        assert self.resource_cnt != 0, 'Operator has NO resources!'

    @staticmethod
    def _get_solana_accounts() -> List[SolanaAccount]:
        return get_solana_accounts()

    @property
    def resource_cnt(self) -> int:
        return self._resource_cnt

    @staticmethod
    def _get_current_time() -> int:
        return math.ceil(datetime.now().timestamp())

    def _get_resource_impl(self, neon_sig: str) -> Optional[OperatorResourceIdent]:
        resource = self._used_resource_dict.get(neon_sig, None)
        if resource is not None:
            return resource

        if len(self._free_resource_list):
            resource = self._free_resource_list.pop(0)
            self._used_resource_dict[neon_sig] = resource
            return resource

        return None

    def get_resource(self, neon_sig: str) -> Optional[str]:
        resource = self._get_resource_impl(neon_sig)
        if resource is None:
            return None

        current_time = self._get_current_time()
        resource.set_last_used_time(current_time)

        resource_info = OperatorResourceInfo.from_ident(resource.ident)
        self.debug(
            f'Resource is selected: {str(resource_info)}, ' +
            f'holder: {str(resource_info.holder)}, ' +
            f'ether: {str(resource_info.ether)}'
        )
        return resource.ident

    def update_resource(self, neon_sig: str) -> None:
        resource = self._used_resource_dict.get(neon_sig, None)
        if resource is not None:
            current_time = self._get_current_time()
            resource.set_last_used_time(current_time)

    def release_resource(self, neon_sig: str) -> None:
        resource = self._used_resource_dict.pop(neon_sig, None)
        if resource is None:
            return

        recheck_cnt = self._config.get_recheck_resource_after_uses_cnt()
        if resource.used_cnt > recheck_cnt:
            self._disabled_resource_list.append(resource)
        else:
            self._free_resource_list.append(resource)

    def enable_resource(self, ident: str) -> None:
        for i, resource in enumerate(self._disabled_resource_list):
            if resource.ident == ident:
                self._disabled_resource_list.pop(i)
                resource.reset_used_cnt()
                self._free_resource_list.append(resource)
                break

    def get_disabled_resource_list(self) -> List[str]:
        current_time = self._get_current_time()

        recheck_sec = self._config.get_recheck_used_resource_sec()
        check_time = current_time - recheck_sec
        old_resource_list: List[str, OperatorResourceIdent] = []
        for neon_sig, resource in self._used_resource_dict.items():
            if resource.last_used_time < check_time:
                self._disabled_resource_list.append(resource)
                old_resource_list.append(neon_sig)
        for neon_sig in old_resource_list:
            self._used_resource_dict.pop(neon_sig)

        return [resource.ident for resource in self._disabled_resource_list]
