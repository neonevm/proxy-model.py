from __future__ import annotations

import math
import traceback
from datetime import datetime
from typing import Dict, Optional, List

from logged_groups import logged_group
from solana.account import Account as SolanaAccount
from solana.publickey import PublicKey

from ..common_neon.address import EthereumAddress, ether2program
from ..common_neon.constants import STORAGE_SIZE, ACTIVE_STORAGE_TAG, FINALIZED_STORAGE_TAG, EMPTY_STORAGE_TAG
from ..common_neon.solana_tx_list_sender import SolTxListInfo, SolTxListSender
from ..common_neon.environment_utils import get_solana_accounts
from ..common_neon.environment_data import EVM_LOADER_ID, PERM_ACCOUNT_LIMIT, RECHECK_RESOURCE_LIST_INTERVAL
from ..common_neon.environment_data import MIN_OPERATOR_BALANCE_TO_WARN, MIN_OPERATOR_BALANCE_TO_ERR
from ..common_neon.cancel_transaction_executor import CancelTxExecutor
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.neon_instruction import NeonIxBuilder

from .neon_tx_stages import NeonCreateAccountTxStage, NeonCreatePermAccount, NeonTxStage


@logged_group("neon.MemPool")
class OperatorResourceInfo:
    def __init__(self, signer: SolanaAccount, rid: int, idx: int):
        self.signer = signer
        self.rid = rid
        self.idx = idx
        self.check_time = 0
        self.ether: Optional[EthereumAddress] = None
        self.storage: Optional[PublicKey] = None
        self.holder: Optional[PublicKey] = None
        self.seed_list = None

    def fill_storage_holder(self):
        self.ether = EthereumAddress.from_private_key(self.secret_key)
        aid = self.rid.to_bytes(math.ceil(self.rid.bit_length() / 8), 'big')
        self.seed_list = [prefix + aid for prefix in [b"storage", b"holder"]]
        builder = NeonIxBuilder(self.public_key)
        stage_list = [NeonCreatePermAccount(builder, seed, STORAGE_SIZE) for seed in self.seed_list]
        self.storage, self.holder = [s.sol_account for s in stage_list]

    def __str__(self) -> str:
        return f'{str(self.public_key)}:{self.rid}'

    @property
    def public_key(self) -> PublicKey:
        return self.signer.public_key()

    @property
    def secret_key(self) -> bytes:
        return self.signer.secret_key()

@logged_group("neon.MemPool")
class ResourceInitializer:
    def __init__(self, solana: SolanaInteractor):
        self._solana = solana

    def init_resource(self, resource: OperatorResourceInfo):
        return self._init_perm_accounts(resource)

    @staticmethod
    def _get_current_time() -> int:
        return math.ceil(datetime.now().timestamp())

    @staticmethod
    def _min_operator_balance_to_err() -> int:
        return MIN_OPERATOR_BALANCE_TO_ERR

    @staticmethod
    def _min_operator_balance_to_warn() -> int:
        return MIN_OPERATOR_BALANCE_TO_WARN

    def _init_perm_accounts(self, resource: OperatorResourceInfo) -> bool:
        resource.fill_storage_holder()

        check_time = self._get_current_time() + RECHECK_RESOURCE_LIST_INTERVAL
        resource_check_time = resource.check_time

        if resource_check_time and resource_check_time < check_time:
            return True

        self.debug(f'Rechecking of accounts for resource {resource} {resource_check_time} > {check_time}')

        try:
            self._validate_operator_balance(resource)

            builder = NeonIxBuilder(resource.public_key)
            stage_list = self._create_perm_accounts(builder, resource)
            stage_list += self._create_ether_account(builder, resource)

            if len(stage_list) == 0:
                return True

            tx_list_info = SolTxListInfo(
                name_list=[s.NAME for s in stage_list],
                tx_list=[s.tx for s in stage_list]
            )
            SolTxListSender(self._solana, resource.signer).send(tx_list_info)
            return True
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f"Fail to init accounts for resource {resource}, err({err}): {err_tb}")
            return False

    def _validate_operator_balance(self, resource: OperatorResourceInfo) -> None:
        # Validate operator's account has enough SOLs
        sol_balance = self._solana.get_sol_balance(resource.public_key)
        min_operator_balance_to_err = self._min_operator_balance_to_err()
        if sol_balance <= min_operator_balance_to_err:
            self.error(
                f'Operator account {resource} has NOT enough SOLs; balance = {sol_balance}; ' +
                f'min_operator_balance_to_err = {min_operator_balance_to_err}'
            )
            raise RuntimeError('Not enough SOLs')

        min_operator_balance_to_warn = self._min_operator_balance_to_warn()
        if sol_balance <= min_operator_balance_to_warn:
            self.warning(
                f'Operator account {resource} SOLs are running out; balance = {sol_balance}; ' +
                f'min_operator_balance_to_warn = {min_operator_balance_to_warn}; ' +
                f'min_operator_balance_to_err = {min_operator_balance_to_err}; '
            )

    def _create_ether_account(self, builder: NeonIxBuilder, resource: OperatorResourceInfo) -> List[NeonTxStage]:
        ether_address = EthereumAddress.from_private_key(resource.secret_key)
        solana_address = ether2program(ether_address)[0]
        resource.ether = ether_address

        account_info = self._solana.get_account_info(solana_address)
        if account_info is not None:
            self.debug(f"Use existing ether account {str(solana_address)} for resource {resource}")
            return []

        stage = NeonCreateAccountTxStage(builder, {"address": ether_address})
        stage.set_balance(self._solana.get_multiple_rent_exempt_balances_for_size([stage.size])[0])
        stage.build()

        self.debug(f"Create new ether account {str(solana_address)} for resource {resource}")

        return [stage]

    def _create_perm_accounts(self, builder: NeonIxBuilder, resource: OperatorResourceInfo):
        result_stage_list: List[NeonTxStage] = []
        stage_list = [NeonCreatePermAccount(builder, seed, STORAGE_SIZE) for seed in resource.seed_list]
        account_list = [s.sol_account for s in stage_list]
        info_list = self._solana.get_account_info_list(account_list)
        balance = self._solana.get_multiple_rent_exempt_balances_for_size([STORAGE_SIZE])[0]
        for idx, account, stage in zip(range(len(resource.seed_list)), info_list, stage_list):
            if not account:
                self.debug(f"Create new accounts for resource {resource}")
                stage.set_balance(balance)
                stage.build()
                result_stage_list.append(stage)
                continue
            elif account.lamports < balance:
                raise RuntimeError(f"insufficient balance of {str(stage.sol_account)}")
            elif account.owner != PublicKey(EVM_LOADER_ID):
                raise RuntimeError(f"wrong owner for: {str(stage.sol_account)}")
            elif idx != 0:
                continue

            if account.tag == ACTIVE_STORAGE_TAG:
                self._unlock_storage_account(resource, stage.sol_account)
            elif account.tag not in (FINALIZED_STORAGE_TAG, EMPTY_STORAGE_TAG):
                raise RuntimeError(f"not empty, not finalized: {str(stage.sol_account)}")

        if len(result_stage_list) == 0:
            self.debug(f"Use existing accounts for resource {resource}")
        resource.storage = account_list[0]
        resource.holder = account_list[1]
        return result_stage_list

    def _unlock_storage_account(self, resource: OperatorResourceInfo, storage_account: PublicKey) -> None:
        self.debug(f"Cancel transaction in {str(storage_account)} for resource {resource}")
        storage_info = self._solana.get_storage_account_info(storage_account)
        cancel_tx_executor = CancelTxExecutor(self._solana, resource.signer)
        cancel_tx_executor.add_blocked_storage_account(storage_info)
        cancel_tx_executor.execute_tx_list()


@logged_group("neon.MemPool")
class OperatorResourceManager:
    _free_resource_list = list()
    _bad_resource_list = list()
    _resource_list: List[OperatorResourceInfo] = []
    _allocated_resource: Dict[str, int] = dict()
    _allocated_resource_access: Dict[str, int] = dict()

    def __init__(self):
        self._init_resource_list()

    def _init_resource_list(self):
        idx = 0
        signer_list: List[SolanaAccount] = get_solana_accounts()
        for rid in range(PERM_ACCOUNT_LIMIT):
            for signer in signer_list:
                info = OperatorResourceInfo(signer=signer, rid=rid, idx=idx)
                self._resource_list.append(info)
                idx += 1

        for idx in range(len(self._resource_list)):
            self._free_resource_list.append(idx)

        if len(self._resource_list) == 0:
            raise RuntimeError('Operator has NO resources!')

    @staticmethod
    def recheck_resource_list_interval() -> int:
        return RECHECK_RESOURCE_LIST_INTERVAL

    @staticmethod
    def _get_current_time() -> int:
        return math.ceil(datetime.now().timestamp())

    def recheck_bad_resource_list(self) -> int:
        if not len(self._bad_resource_list):
            return

        for idx in self._bad_resource_list:
            self._free_resource_list.append(idx)

        del self._bad_resource_list[:]

    def get_resource(self, tx_hash: str) -> Optional[OperatorResourceInfo]:
        current_time: int = self._get_current_time()
        resource: Optional[OperatorResourceInfo] = None

        if self._allocated_resource.get(tx_hash) is not None:
            idx = self._allocated_resource[tx_hash]
            resource = self._resource_list[idx]

        if len(self._free_resource_list) > 0:
            idx = self._free_resource_list.pop(0)
            resource = self._resource_list[idx]
            self._allocated_resource[tx_hash] = idx
            self._allocated_resource_access[tx_hash] = current_time
        else:
            for blocked_tx_hash, access_time in self._allocated_resource_access:
                if current_time - access_time > self.RECHECK_RESOURCE_LIST_INTERVAL:
                    idx = self._allocated_resource[blocked_tx_hash]
                    resource = self._resource_list[idx]
                    del self._allocated_resource[blocked_tx_hash]
                    del self._allocated_resource_access[blocked_tx_hash]
                    self._allocated_resource[tx_hash] = idx
                    self._allocated_resource_access[tx_hash] = current_time
                    break

        self.debug(
            f'Resource is selected: {str(resource)}, ' +
            f'storage: {str(resource.storage)}, ' +
            f'holder: {str(resource.holder)}, ' +
            f'ether: {str(resource.ether)}'
        )
        return resource

    def update_allocated_resource(self, tx_hash: str, resource: OperatorResourceInfo) -> None:
        current_time: int = self._get_current_time()
        self._allocated_resource_access[tx_hash] = current_time
        self._resource_list[resource.idx].check_time = current_time

    def bad_resource_info(self, tx_hash: str, resource: OperatorResourceInfo) -> None:
        del self._allocated_resource[tx_hash]
        del self._allocated_resource_access[tx_hash]
        self._resource_list[resource.idx].check_time = 0
        self._bad_resource_list.append(resource.idx)

    def free_resource_info(self, tx_hash: str, resource: OperatorResourceInfo) -> None:
        current_time: int = self._get_current_time()
        del self._allocated_resource[tx_hash]
        del self._allocated_resource_access[tx_hash]
        self._resource_list[resource.idx].check_time = current_time
        self._free_resource_list.append(resource.idx)
