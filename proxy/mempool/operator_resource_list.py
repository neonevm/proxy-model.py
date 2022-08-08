from __future__ import annotations

import math
import traceback
from datetime import datetime
from typing import Optional, List

from logged_groups import logged_group
from solana.account import Account as SolanaAccount
from solana.publickey import PublicKey

from ..common_neon.address import EthereumAddress, ether2program
from ..common_neon.compute_budget import TransactionWithComputeBudget
from ..common_neon.constants import STORAGE_SIZE, ACTIVE_STORAGE_TAG, FINALIZED_STORAGE_TAG, EMPTY_STORAGE_TAG
from ..common_neon.solana_tx_list_sender import SolTxListSender
from ..common_neon.environment_utils import get_solana_accounts
from ..common_neon.environment_data import EVM_LOADER_ID, PERM_ACCOUNT_LIMIT, RECHECK_RESOURCE_LIST_INTERVAL
from ..common_neon.environment_data import MIN_OPERATOR_BALANCE_TO_WARN, MIN_OPERATOR_BALANCE_TO_ERR
from ..common_neon.cancel_transaction_executor import CancelTxExecutor
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.neon_instruction import NeonIxBuilder

from .neon_tx_stages import NeonCreateAccountTxStage, NeonCreatePermAccount


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

    def __str__(self) -> str:
        return f'{str(self.public_key)}:{self.rid}'

    @property
    def public_key(self) -> PublicKey:
        return self.signer.public_key()

    @property
    def secret_key(self) -> bytes:
        return self.signer.secret_key()

    @staticmethod
    def _get_current_time() -> int:
        return math.ceil(datetime.now().timestamp())

    def init_perm_accounts(self, solana: SolanaInteractor) -> bool:
        check_time = self._get_current_time() + RECHECK_RESOURCE_LIST_INTERVAL
        resource_check_time = self.check_time

        if resource_check_time > check_time:
            self.check_time = self._get_current_time()
            self.debug(f'Rechecking of accounts for resource {self} {resource_check_time} > {check_time}')
        elif self.storage and self.holder and self.ether:
            return True

        aid = self.rid.to_bytes(math.ceil(self.rid.bit_length() / 8), 'big')
        seed_list = [prefix + aid for prefix in [b"storage", b"holder"]]

        try:
            self._validate_operator_balance(solana)

            builder = NeonIxBuilder(self.public_key)
            storage, holder = self._create_perm_accounts(solana, builder, seed_list)
            ether = self._create_ether_account(solana, builder)
            self.ether = ether
            self.storage = storage
            self.holder = holder
            return True
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f"Fail to init accounts for resource {self}, err({err}): {err_tb}")
            return False

    @staticmethod
    def _min_operator_balance_to_err() -> int:
        return MIN_OPERATOR_BALANCE_TO_ERR

    @staticmethod
    def _min_operator_balance_to_warn() -> int:
        return MIN_OPERATOR_BALANCE_TO_WARN

    def _validate_operator_balance(self, solana: SolanaInteractor) -> None:
        # Validate operator's account has enough SOLs
        sol_balance = solana.get_sol_balance(self.public_key)
        min_operator_balance_to_err = self._min_operator_balance_to_err()
        if sol_balance <= min_operator_balance_to_err:
            self.error(f'Operator account {self} has NOT enough SOLs; balance = {sol_balance}; ' +
                       f'min_operator_balance_to_err = {min_operator_balance_to_err}')
            raise RuntimeError('Not enough SOLs')

        min_operator_balance_to_warn = self._min_operator_balance_to_warn()
        if sol_balance <= min_operator_balance_to_warn:
            self.warning(f'Operator account {self} SOLs are running out; balance = {sol_balance}; ' +
                         f'min_operator_balance_to_warn = {min_operator_balance_to_warn}; ' +
                         f'min_operator_balance_to_err = {min_operator_balance_to_err}; ')

    def _create_ether_account(self, solana: SolanaInteractor, builder: NeonIxBuilder) -> EthereumAddress:
        ether_address = EthereumAddress.from_private_key(self.secret_key)
        solana_address = ether2program(ether_address)[0]

        account_info = solana.get_account_info(solana_address)
        if account_info is not None:
            self.debug(f"Use existing ether account {str(solana_address)} for resource {self}")
            return ether_address

        stage = NeonCreateAccountTxStage(builder, {"address": ether_address})
        stage.set_balance(solana.get_multiple_rent_exempt_balances_for_size([stage.size])[0])
        stage.build()

        self.debug(f"Create new ether account {str(solana_address)} for resource {self}")
        SolTxListSender(solana, self.signer).send(NeonCreateAccountTxStage.NAME, [stage.tx])

        return ether_address

    def _create_perm_accounts(self, solana: SolanaInteractor, builder: NeonIxBuilder, seed_list: List[bytes]):
        tx = TransactionWithComputeBudget()
        tx_name_list = set()

        stage_list = [NeonCreatePermAccount(builder, seed, STORAGE_SIZE) for seed in seed_list]
        account_list = [s.sol_account for s in stage_list]
        info_list = solana.get_account_info_list(account_list)
        balance = solana.get_multiple_rent_exempt_balances_for_size([STORAGE_SIZE])[0]
        for idx, account, stage in zip(range(len(seed_list)), info_list, stage_list):
            if not account:
                self.debug(f"Create new accounts for resource {self}")
                stage.set_balance(balance)
                stage.build()
                tx_name_list.add(stage.NAME)
                tx.add(stage.tx)
                continue
            elif account.lamports < balance:
                raise RuntimeError(f"insufficient balance of {str(stage.sol_account)}")
            elif account.owner != PublicKey(EVM_LOADER_ID):
                raise RuntimeError(f"wrong owner for: {str(stage.sol_account)}")
            elif idx != 0:
                continue

            if account.tag == ACTIVE_STORAGE_TAG:
                self._unlock_storage_account(solana, stage.sol_account)
            elif account.tag not in (FINALIZED_STORAGE_TAG, EMPTY_STORAGE_TAG):
                raise RuntimeError(f"not empty, not finalized: {str(stage.sol_account)}")

        if len(tx_name_list):
            SolTxListSender(solana, self.signer).send(' + '.join(tx_name_list), [tx])
        else:
            self.debug(f"Use existing accounts for resource {self}")
        return account_list

    def _unlock_storage_account(self, solana: SolanaInteractor, storage_account: PublicKey) -> None:
        self.debug(f"Cancel transaction in {str(storage_account)} for resource {self}")
        storage_info = solana.get_storage_account_info(storage_account)
        cancel_tx_executor = CancelTxExecutor(self._solana, self.signer)
        cancel_tx_executor.add_blocked_storage_account(storage_info)
        cancel_tx_executor.execute_tx_list()


@logged_group("neon.MemPool")
class OperatorResourceManager:
    RECHECK_RESOURCE_LIST_INTERVAL = RECHECK_RESOURCE_LIST_INTERVAL

    _free_resource_list = list()
    _bad_resource_list = list()
    _resource_list: List[OperatorResourceInfo] = []

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

    def recheck_bad_resource_list(self) -> int:
        if not len(self._bad_resource_list):
            return

        for idx in self._bad_resource_list:
            self._free_resource_list.append(idx)

        del self._bad_resource_list[:]

    def get_resource(self) -> Optional[OperatorResourceInfo]:
        if len(self._free_resource_list) == 0:
            return None
        idx = self._free_resource_list.pop(0)
        resource = self._resource_list[idx]
        self.debug(f'Resource is selected: {str(resource)}, ' +
                    f'storage: {str(resource.storage)}, ' +
                    f'holder: {str(resource.holder)}, ' +
                    f'ether: {str(resource.ether)}')
        return resource

    def bad_resource_info(self, resource: OperatorResourceInfo) -> None:
        self._resource_list[resource.idx] = resource
        self._bad_resource_list.append(resource.idx)

    def free_resource_info(self, resource: OperatorResourceInfo) -> None:
        self._resource_list[resource.idx] = resource
        self._free_resource_list.append(resource.idx)
