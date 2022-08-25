from __future__ import annotations

import abc
import asyncio
import math
import traceback
from datetime import datetime
from typing import Dict, Optional, List

from logged_groups import logged_group
from solana.account import Account as SolanaAccount
from solana.publickey import PublicKey

from ..common_neon.config import IConfig
from ..common_neon.address import EthereumAddress, ether2program
from ..common_neon.constants import ACTIVE_STORAGE_TAG, FINALIZED_STORAGE_TAG, EMPTY_STORAGE_TAG
from ..common_neon.solana_tx_list_sender import SolTxListInfo, SolTxListSender
from ..common_neon.environment_utils import get_solana_accounts
from ..common_neon.cancel_transaction_executor import CancelTxExecutor
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.neon_instruction import NeonIxBuilder

from .neon_tx_stages import NeonTxStage, NeonCreateAccountTxStage, NeonCreatePermAccountStage, NeonDeletePermAccountStage


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
    def __init__(self, config: IConfig, solana: SolanaInteractor):
        self._config = config
        self._solana = solana

    def init_resource(self, resource: OperatorResourceInfo):
        return self._init_perm_accounts(resource)

    @staticmethod
    def _get_current_time() -> int:
        return math.ceil(datetime.now().timestamp())

    def _init_perm_accounts(self, resource: OperatorResourceInfo) -> bool:
        self._fill_storage_holder(resource)

        check_time = self._get_current_time() + self._config.get_recheck_resource_list_interval()
        resource_check_time = resource.check_time

        if resource_check_time and resource_check_time < check_time:
            return True

        self.debug(f'Rechecking of accounts for resource {resource} {resource_check_time} > {check_time}')

        try:
            self._validate_operator_balance(resource)

            builder = NeonIxBuilder(resource.public_key)
            stage_list, refund_list = self._create_perm_accounts(builder, resource)
            stage_list += self._create_ether_account(builder, resource)

            if len(stage_list) == 0:
                return True

            if len(refund_list):
                refund_tx_list_info = SolTxListInfo(
                    name_list=[s.NAME for s in refund_list],
                    tx_list=[s.tx for s in refund_list]
                )
                SolTxListSender(self._solana, resource.signer).send(refund_tx_list_info)

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

    def _fill_storage_holder(self, resource_info: OperatorResourceInfo):
        resource_info.ether = EthereumAddress.from_private_key(resource_info.secret_key)
        aid = resource_info.rid.to_bytes(math.ceil(resource_info.rid.bit_length() / 8), 'big')
        resource_info.seed_list = [prefix + aid for prefix in [b"storage", b"holder"]]
        builder = NeonIxBuilder(resource_info.public_key)
        stage_list = [NeonCreatePermAccountStage(builder, seed, 0) for seed in resource_info.seed_list]
        resource_info.storage, resource_info.holder = [s.sol_account for s in stage_list]

    def _validate_operator_balance(self, resource: OperatorResourceInfo) -> None:
        # Validate operator's account has enough SOLs
        sol_balance = self._solana.get_sol_balance(resource.public_key)
        min_operator_balance_to_err = self._config.get_min_operator_balance_to_err()
        if sol_balance <= min_operator_balance_to_err:
            self.error(
                f'Operator account {resource} has NOT enough SOLs; balance = {sol_balance}; ' +
                f'min_operator_balance_to_err = {min_operator_balance_to_err}'
            )
            raise RuntimeError('Not enough SOLs')

        min_operator_balance_to_warn = self._config.get_min_operator_balance_to_warn()
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
        refund_stage_list: List[NeonTxStage] = []

        stage_list = [NeonCreatePermAccountStage(builder, seed, self._config.get_storage_size()) for seed in resource.seed_list]
        account_list = [s.sol_account for s in stage_list]
        info_list = self._solana.get_account_info_list(account_list)
        balance = self._solana.get_multiple_rent_exempt_balances_for_size([self._config.get_storage_size()])[0]
        for idx, account, stage in zip(range(len(resource.seed_list)), info_list, stage_list):
            if not account:
                self._make_create_acc_tx(resource, result_stage_list, balance, idx, stage)
                continue
            elif account.lamports < balance:
                self._make_refund_tx(builder, resource, refund_stage_list, idx, stage)
                self._make_create_acc_tx(resource, result_stage_list, balance, idx, stage)
                continue
            elif account.owner != self._config.get_evm_loader_id():
                raise RuntimeError(f"wrong owner for: {str(stage.sol_account)}")
            elif idx != 0:
                # if not storage account
                continue

            if account.tag == ACTIVE_STORAGE_TAG:
                self._unlock_storage_account(resource, stage.sol_account)
            elif account.tag not in (FINALIZED_STORAGE_TAG, EMPTY_STORAGE_TAG):
                raise RuntimeError(f"not empty, not finalized: {str(stage.sol_account)}")

        if len(result_stage_list) == 0:
            self.debug(f"Use existing accounts for resource {resource}")
        resource.storage = account_list[0]
        resource.holder = account_list[1]
        return result_stage_list, refund_stage_list

    def _make_refund_tx(
            self,
            builder: NeonIxBuilder,
            resource: OperatorResourceInfo,
            refund_stage_list: List[NeonTxStage],
            idx: int,
            stage: NeonCreatePermAccountStage
        ):
        self.debug(f"Add refund stage for: idx: {idx}, seed: {stage.get_seed()}, resource: {resource}")
        refund_stage = NeonDeletePermAccountStage(builder, stage.get_seed())
        refund_stage.build()
        refund_stage_list.append(refund_stage)

    def _make_create_acc_tx(
            self,
            resource: OperatorResourceInfo,
            result_stage_list: List[NeonTxStage],
            balance: int,
            idx: int,
            stage: NeonCreatePermAccountStage
        ):
        self.debug(f"Add create new accounts stage for: idx: {idx}, seed: {stage.get_seed()}, resource: {resource}")
        stage.set_balance(balance)
        stage.build()
        result_stage_list.append(stage)

    def _unlock_storage_account(self, resource: OperatorResourceInfo, storage_account: PublicKey) -> None:
        self.debug(f"Cancel transaction in {str(storage_account)} for resource {resource}")
        storage_info = self._solana.get_storage_account_info(storage_account)
        cancel_tx_executor = CancelTxExecutor(self._solana, resource.signer)
        cancel_tx_executor.add_blocked_storage_account(storage_info)
        cancel_tx_executor.execute_tx_list()


class IOperatorResourceMngUser(abc.ABC):

    @abc.abstractmethod
    def on_operator_resource_released(self):
        pass


class IResourceManager(abc.ABC):

    @abc.abstractmethod
    def get_resource(self, tx_hash: str) -> Optional[OperatorResourceInfo]:
        pass

    @abc.abstractmethod
    def deallocate_resource(self, tx_hash: str) -> None:
        pass

    @abc.abstractmethod
    def on_bad_resource_info(self, tx_hash: str) -> None:
        pass

    @abc.abstractmethod
    def release_resource_info(self, tx_hash: str) -> None:
        pass

    @abc.abstractmethod
    def update_allocated_resource(self, tx_hash: str) -> None:
        pass


@logged_group("neon.MemPool")
class OperatorResourceMng(IResourceManager):

    def __init__(self, user: IOperatorResourceMngUser, config: IConfig):
        self._user = user
        self._free_resource_list: List[int] = list()
        self._bad_resource_list: List[int] = list()
        self._resource_list: List[OperatorResourceInfo] = []
        self._allocated_resource: Dict[str, int] = dict()
        self._allocated_resource_access: Dict[str, int] = dict()
        self._config = config

        self._init_resource_list()
        self._check_resources_task = asyncio.get_event_loop().create_task(self._check_resources_schedule())

    def _init_resource_list(self):
        idx = 0
        signer_list: List[SolanaAccount] = self._get_solana_accounts()
        for rid in range(self._config.get_perm_account_limit()):
            for signer in signer_list:
                info = OperatorResourceInfo(signer=signer, rid=rid, idx=idx)
                self._resource_list.append(info)
                idx += 1

        for idx in range(len(self._resource_list)):
            self._free_resource_list.append(idx)

        if len(self._resource_list) == 0:
            raise RuntimeError('Operator has NO resources!')

    @staticmethod
    def _get_solana_accounts() -> List[SolanaAccount]:
        return get_solana_accounts()

    @staticmethod
    def _get_current_time() -> int:
        return math.ceil(datetime.now().timestamp())

    def _recheck_bad_resource_list(self):
        if not len(self._bad_resource_list):
            return

        for idx in self._bad_resource_list:
            self._free_resource_list.append(idx)

        del self._bad_resource_list[:]

    def get_resource(self, tx_hash: str) -> Optional[OperatorResourceInfo]:
        current_time: int = self._get_current_time()
        resource: Optional[OperatorResourceInfo] = None

        resource_idx = self._allocated_resource.get(tx_hash)
        if resource_idx is not None:
            resource = self._resource_list[resource_idx]
            return resource

        if len(self._free_resource_list) > 0:
            idx = self._free_resource_list.pop(0)
            resource = self._resource_list[idx]
            self._allocated_resource[tx_hash] = idx
            self._allocated_resource_access[tx_hash] = current_time
        else:
            for blocked_tx_hash, access_time in self._allocated_resource_access:
                if current_time - access_time > self._config.get_recheck_resource_list_interval():
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

    def _tx_hash_based(method):
        def wrapper(self, tx_hash: str):
            resource_idx = self._allocated_resource.get(tx_hash)
            if resource_idx is None:
                self.error(f"Failed to process {method.__name__}, resource not found for tx_hash: {tx_hash}")
                return
            method(self, resource_idx, tx_hash)
        return wrapper

    @_tx_hash_based
    def update_allocated_resource(self, resource_idx: int, tx_hash: str) -> None:
        current_time: int = self._get_current_time()
        # TODO: the only one place to put current_time is enough
        self._allocated_resource_access[tx_hash] = current_time
        self._resource_list[resource_idx].check_time = current_time

    @_tx_hash_based
    def on_bad_resource_info(self, resource_idx: int, tx_hash: str) -> None:
        del self._allocated_resource[tx_hash]
        del self._allocated_resource_access[tx_hash]
        self._resource_list[resource_idx].check_time = 0
        self._bad_resource_list.append(resource_idx)

    @_tx_hash_based
    def release_resource_info(self, resource_idx: int, tx_hash: str) -> None:
        current_time: int = self._get_current_time()
        del self._allocated_resource[tx_hash]
        del self._allocated_resource_access[tx_hash]
        self._resource_list[resource_idx].check_time = current_time
        self._free_resource_list.append(resource_idx)
        self._user.on_operator_resource_released()

    # TODO: check if it can be dropped from here
    @_tx_hash_based
    def deallocate_resource(self, resource_idx: int, tx_hash: str) -> None:
        del self._allocated_resource[tx_hash]
        del self._allocated_resource_access[tx_hash]
        self._free_resource_list.append(resource_idx)
        self._user.on_operator_resource_released()

    async def _check_resources_schedule(self):
        while True:
            self._recheck_bad_resource_list()
            await asyncio.sleep(self._config.get_recheck_resource_list_interval())

