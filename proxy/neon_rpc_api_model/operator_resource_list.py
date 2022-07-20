import ctypes
import math
import multiprocessing as mp
import time
import traceback
from datetime import datetime
from typing import Optional, List

import sha3
from logged_groups import logged_group
from solana.account import Account as SolanaAccount
from solana.transaction import AccountMeta
from solana.publickey import PublicKey

from ..common_neon.address import EthereumAddress, ether2program, accountWithSeed
from ..common_neon.compute_budget import TransactionWithComputeBudget
from ..common_neon.constants import STORAGE_SIZE, ACTIVE_STORAGE_TAG, FINALIZED_STORAGE_TAG, EMPTY_STORAGE_TAG
from ..common_neon.solana_tx_list_sender import SolTxListSender
from ..common_neon.environment_utils import get_solana_accounts
from ..common_neon.environment_data import EVM_LOADER_ID, PERM_ACCOUNT_LIMIT, RECHECK_RESOURCE_LIST_INTERVAL
from ..common_neon.environment_data import MIN_OPERATOR_BALANCE_TO_WARN, MIN_OPERATOR_BALANCE_TO_ERR
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.neon_instruction import NeonIxBuilder

from .neon_tx_stages import NeonCreateAccountTxStage, NeonCreateAccountWithSeedStage


class OperatorResourceInfo:
    def __init__(self, signer: SolanaAccount, rid: int, idx: int):
        self.signer = signer
        self.rid = rid
        self.idx = idx
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


@logged_group("neon.Proxy")
class OperatorResourceList:
    # These variables are global for class, they will be initialized one time
    _manager = mp.Manager()
    _free_resource_list = _manager.list()
    _bad_resource_list = _manager.list()
    _check_time_resource_list = _manager.list()
    _resource_list_len = mp.Value(ctypes.c_uint, 0)
    _last_checked_time = mp.Value(ctypes.c_ulonglong, 0)
    _resource_list: List[OperatorResourceInfo] = []

    def __init__(self, solana: SolanaInteractor):
        self._solana = solana

    @staticmethod
    def _get_current_time() -> int:
        return math.ceil(datetime.now().timestamp())

    def _init_resource_list(self):
        if len(self._resource_list):
            return

        idx = 0
        signer_list: List[SolanaAccount] = get_solana_accounts()
        for rid in range(PERM_ACCOUNT_LIMIT):
            for signer in signer_list:
                info = OperatorResourceInfo(signer=signer, rid=rid, idx=idx)
                self._resource_list.append(info)
                idx += 1

        with self._resource_list_len.get_lock():
            if self._resource_list_len.value != 0:
                return True

            for idx in range(len(self._resource_list)):
                self._free_resource_list.append(idx)
                self._check_time_resource_list.append(0)

            self._resource_list_len.value = len(self._resource_list)
            if self._resource_list_len.value == 0:
                raise RuntimeError('Operator has NO resources!')

    def _recheck_bad_resource_list(self) -> int:
        def is_time_come(t1: float, t2: float) -> int:
            time_diff = t1 - t2
            return time_diff > RECHECK_RESOURCE_LIST_INTERVAL

        now = self._get_current_time()
        prev_time = self._last_checked_time.value
        if not is_time_come(now, prev_time):
            return prev_time

        with self._last_checked_time.get_lock():
            prev_time = self._last_checked_time.value
            if not is_time_come(now, prev_time):
                return prev_time
            self._last_checked_time.value = now

        with self._resource_list_len.get_lock():
            if not len(self._bad_resource_list):
                return now

            self._resource_list_len.value += len(self._bad_resource_list)
            for idx in self._bad_resource_list:
                self._free_resource_list.append(idx)

            del self._bad_resource_list[:]
        return now

    def get_available_resource_info(self) -> OperatorResourceInfo:
        self._init_resource_list()
        check_time = self._recheck_bad_resource_list()

        timeout = 0.01
        for i in range(400_000):  # 10'000 blocks!
            if i > 0:
                if i % 40 == 0:  # one block time
                    self.debug(f'Waiting for a free operator resource ({i * timeout})...')
                time.sleep(timeout)

            with self._resource_list_len.get_lock():
                if self._resource_list_len.value == 0:
                    raise RuntimeError('Operator has NO resources!')
                elif len(self._free_resource_list) == 0:
                    continue
                idx = self._free_resource_list.pop(0)

            resource = self._resource_list[idx]
            if not self._init_perm_accounts(check_time, resource):
                continue

            self.debug(f'Resource is selected: {str(resource)}, ' +
                       f'storage: {str(resource.storage)}, ' +
                       f'holder: {str(resource.holder)}, ' +
                       f'ether: {str(resource.ether)}')
            return resource

        raise RuntimeError('Timeout on waiting a free operator resource!')

    def _init_perm_accounts(self, check_time: float, resource: OperatorResourceInfo) -> bool:
        resource_check_time = self._check_time_resource_list[resource.idx]

        if check_time != resource_check_time:
            self._check_time_resource_list[resource.idx] = check_time
            self.debug(f'Rechecking of accounts for resource {resource} {resource_check_time} != {check_time}')
        elif resource.storage and resource.holder and resource.ether:
            return True

        aid = resource.rid.to_bytes(math.ceil(resource.rid.bit_length() / 8), 'big')
        seed_list = [prefix + aid for prefix in [b"storage", b"holder"]]

        try:
            self._validate_operator_balance(resource)

            builder = NeonIxBuilder(resource.public_key)
            storage, holder = self._create_perm_accounts(builder, resource, seed_list)
            ether = self._create_ether_account(builder, resource)
            resource.ether = ether
            resource.storage = storage
            resource.holder = holder
            return True
        except Exception as err:
            self._resource_list_len.value -= 1
            self._bad_resource_list.append(resource.idx)
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f"Fail to init accounts for resource {resource}, err({err}): {err_tb}")
            return False

    @staticmethod
    def _min_operator_balance_to_err() -> int:
        return MIN_OPERATOR_BALANCE_TO_ERR

    @staticmethod
    def _min_operator_balance_to_warn() -> int:
        return MIN_OPERATOR_BALANCE_TO_WARN

    def _validate_operator_balance(self, resource: OperatorResourceInfo) -> None:
        # Validate operator's account has enough SOLs
        sol_balance = self._solana.get_sol_balance(resource.public_key)
        min_operator_balance_to_err = self._min_operator_balance_to_err()
        if sol_balance <= min_operator_balance_to_err:
            self.error(f'Operator account {resource} has NOT enough SOLs; balance = {sol_balance}; ' +
                       f'min_operator_balance_to_err = {min_operator_balance_to_err}')
            raise RuntimeError('Not enough SOLs')

        min_operator_balance_to_warn = self._min_operator_balance_to_warn()
        if sol_balance <= min_operator_balance_to_warn:
            self.warning(f'Operator account {resource} SOLs are running out; balance = {sol_balance}; ' +
                         f'min_operator_balance_to_warn = {min_operator_balance_to_warn}; ' +
                         f'min_operator_balance_to_err = {min_operator_balance_to_err}; ')

    def _create_ether_account(self, builder: NeonIxBuilder, resource: OperatorResourceInfo) -> EthereumAddress:
        ether_address = EthereumAddress.from_private_key(resource.secret_key)
        solana_address = ether2program(ether_address)[0]

        account_info = self._solana.get_account_info(solana_address)
        if account_info is not None:
            self.debug(f"Use existing ether account {str(solana_address)} for resource {resource}")
            return ether_address

        stage = NeonCreateAccountTxStage(builder, {"address": ether_address})
        stage.set_balance(self._solana.get_multiple_rent_exempt_balances_for_size([stage.size])[0])
        stage.build()

        self.debug(f"Create new ether account {str(solana_address)} for resource {resource}")
        SolTxListSender(self._solana, resource.signer).send(NeonCreateAccountTxStage.NAME, [stage.tx])

        return ether_address

    def _create_perm_accounts(self, builder: NeonIxBuilder, resource: OperatorResourceInfo, seed_list: List[bytes]):
        tx = TransactionWithComputeBudget()
        tx_name_list = set()

        stage_list = [NeonCreatePermAccount(builder, seed, STORAGE_SIZE) for seed in seed_list]
        account_list = [s.sol_account for s in stage_list]
        info_list = self._solana.get_account_info_list(account_list)
        balance = self._solana.get_multiple_rent_exempt_balances_for_size([STORAGE_SIZE])[0]
        for idx, account, stage in zip(range(len(seed_list)), info_list, stage_list):
            if not account:
                self.debug(f"Create new accounts for resource {resource}")
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
                self.debug(f"Cancel transaction in {str(stage.sol_account)} for resource {resource}")
                cancel_stage = NeonCancelTxStage(self._solana, builder, stage.sol_account)
                cancel_stage.build()
                tx_name_list.add(cancel_stage.NAME)
                tx.add(cancel_stage.tx)
            elif account.tag not in (FINALIZED_STORAGE_TAG, EMPTY_STORAGE_TAG):
                raise RuntimeError(f"not empty, not finalized: {str(stage.sol_account)}")

        if len(tx_name_list):
            SolTxListSender(self._solana, resource.signer).send(' + '.join(tx_name_list), [tx])
        else:
            self.debug(f"Use existing accounts for resource {resource}")
        return account_list

    def free_resource_info(self, resource: OperatorResourceInfo) -> None:
        self._free_resource_list.append(resource.idx)


class NeonCreatePermAccount(NeonCreateAccountWithSeedStage):
    NAME = 'createPermAccount'

    def __init__(self, builder: NeonIxBuilder, seed_base: bytes, size: int):
        super().__init__(builder)
        self._seed_base = seed_base
        self._size = size
        self._init_sol_account()

    def _init_sol_account(self):
        assert len(self._seed_base) > 0
        seed = sha3.keccak_256(self._seed_base).hexdigest()[:32]
        self._seed = bytes(seed, 'utf8')
        self._sol_account = accountWithSeed(bytes(self._builder.operator_account), self._seed)

    def build(self):
        assert self._is_empty()

        self.debug(f'Create perm account {self.sol_account}')
        self.tx.add(self._create_account_with_seed())


@logged_group("neon.Proxy")
class NeonCancelTxStage:
    NAME = 'cancelWithNonce'

    def __init__(self, solana: SolanaInteractor, builder: NeonIxBuilder, storage_account: PublicKey):
        self._builder = builder
        self.tx = TransactionWithComputeBudget()
        self._account = storage_account
        self._storage = solana.get_storage_account_info(storage_account)

    def _cancel_ix(self):
        key_list = []
        for is_writable, account in self._storage.account_list:
            key_list.append(AccountMeta(pubkey=PublicKey(account), is_signer=False, is_writable=is_writable))

        return self._builder.make_cancel_instruction(
            storage=self._account,
            nonce=self._storage.nonce,
            cancel_keys=key_list
        )

    def _is_empty(self) -> bool:
        return not len(self.tx.signatures)

    def build(self):
        assert self._is_empty()
        assert self._storage is not None

        self.debug(f'Cancel transaction in storage account {str(self._account)}')
        self.tx.add(self._cancel_ix())
