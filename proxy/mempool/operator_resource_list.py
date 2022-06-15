# from __future__ import annotations
# from __future__ import annotations

import abc
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
from solana.publickey import PublicKey

from proxy.mempool.operator_resource_list_2 import OperatorResourceId

from ..common_neon.address import EthereumAddress, ether2program, accountWithSeed
from ..common_neon.compute_budget import TransactionWithComputeBudget
from ..common_neon.constants import STORAGE_SIZE, ACTIVE_STORAGE_TAG, FINALIZED_STORAGE_TAG, EMPTY_STORAGE_TAG
from ..common_neon.solana_tx_list_sender import SolTxListSender
from ..common_neon.environment_utils import get_solana_accounts
from ..common_neon.environment_data import EVM_LOADER_ID, PERM_ACCOUNT_LIMIT, RECHECK_RESOURCE_LIST_INTERVAL, \
                                           MIN_OPERATOR_BALANCE_TO_WARN, MIN_OPERATOR_BALANCE_TO_ERR

from ..mempool.neon_tx_stages import NeonCancelTxStage, NeonCreateAccountTxStage, NeonCreateAccountWithSeedStage
from ..mempool.transaction_sender import NeonTxSender


class OperatorResourceInfo:
    def __init__(self, signer: SolanaAccount, rid: int, idx: int):
        self.signer = signer
        self.rid = rid
        self.idx = idx
        self.ether: Optional[EthereumAddress] = None
        self.storage: Optional[PublicKey] = None
        self.holder: Optional[PublicKey] = None

    def public_key(self) -> PublicKey:
        return self.signer.public_key()

    def secret_key(self) -> bytes:
        return self.signer.secret_key()


@logged_group("neon.MemPool")
class OperatorResourceList:
    # These variables are global for class, they will be initialized one time
    _manager = mp.Manager()
    _free_resource_list = _manager.list()
    _bad_resource_list = _manager.list()
    _check_time_resource_list = _manager.list()
    _resource_list_len = mp.Value(ctypes.c_uint, 0)
    _last_checked_time = mp.Value(ctypes.c_ulonglong, 0)
    _resource_list = []

    @staticmethod
    def _get_current_time() -> int:
        return math.ceil(datetime.now().timestamp())

    @classmethod
    def _init_resource_list(cls):
        if len(cls._resource_list):
            return

        idx = 0
        signer_list: List[SolanaAccount] = get_solana_accounts()
        for rid in range(PERM_ACCOUNT_LIMIT):
            for signer in signer_list:
                info = OperatorResourceInfo(signer=signer, rid=rid, idx=idx)
                cls._resource_list.append(info)
                idx += 1

        with cls._resource_list_len.get_lock():
            if cls._resource_list_len.value != 0:
                return True

            for idx in range(len(cls._resource_list)):
                cls._free_resource_list.append(idx)
                cls._check_time_resource_list.append(0)

            cls._resource_list_len.value = len(cls._resource_list)
            if cls._resource_list_len.value == 0:
                raise RuntimeError('Operator has NO resources!')

    @classmethod
    def _recheck_bad_resource_list(cls):
        def is_time_come(now, prev_time):
            time_diff = now - prev_time
            return time_diff > RECHECK_RESOURCE_LIST_INTERVAL

        now = cls._get_current_time()
        prev_time = cls._last_checked_time.value
        if not is_time_come(now, prev_time):
            return prev_time

        with cls._last_checked_time.get_lock():
            prev_time = cls._last_checked_time.value
            if not is_time_come(now, prev_time):
                return prev_time
            cls._last_checked_time.value = now

        with cls._resource_list_len.get_lock():
            if not len(cls._bad_resource_list):
                return now

            cls._resource_list_len.value += len(cls._bad_resource_list)
            for idx in cls._bad_resource_list:
                cls._free_resource_list.append(idx)

            del cls._bad_resource_list[:]
        return now

    @classmethod
    def get_active_resource(cls, sender: NeonTxSender) -> OperatorResourceId:
        cls._init_resource_list(cls)
        check_time = cls._recheck_bad_resource_list(cls)

        timeout = 0.01
        for i in range(400_000):  # 10'000 blocks!
            if i > 0:
                if i % 40 == 0:  # one block time
                    cls.debug(f'Waiting for a free operator resource ({i * timeout})...')
                time.sleep(timeout)

            with cls._resource_list_len.get_lock():
                if cls._resource_list_len.value == 0:
                    raise RuntimeError('Operator has NO resources!')
                elif len(cls._free_resource_list) == 0:
                    continue
                idx = cls._free_resource_list.pop(0)

            resource = cls._resource_list[idx]
            sender.set_resource(resource)
            if not cls._init_perm_accounts(cls, check_time, sender):
                sender.clear_resource()
                continue

            cls.debug(f'Resource is selected: {str(resource.public_key())}:{resource.rid}, ' +
                       f'storage: {str(resource.storage)}, ' +
                       f'holder: {str(resource.holder)}, ' +
                       f'ether: {str(resource.ether)}')
            return idx

        raise RuntimeError('Timeout on waiting a free operator resource!')

    @classmethod
    def _init_perm_accounts(cls, check_time, sender: NeonTxSender) -> bool:
        opkey = str(sender.resource.public_key())
        rid = sender.resource.rid

        resource_check_time = cls._check_time_resource_list[sender.resource.idx]

        if check_time != resource_check_time:
            cls._check_time_resource_list[sender.resource.idx] = check_time
            cls.debug(f'Rechecking of accounts for resource {opkey}:{rid} {resource_check_time} != {check_time}')
        elif sender.resource.storage and sender.resource.holder and sender.resource.ether:
            return True

        aid = rid.to_bytes(math.ceil(rid.bit_length() / 8), 'big')
        seed_list = [prefix + aid for prefix in [b"storage", b"holder"]]

        try:
            cls._validate_operator_balance(cls, sender)

            storage, holder = cls._create_perm_accounts(cls, seed_list)
            ether = cls._create_ether_account(cls)
            sender.resource.ether = ether
            sender.resource.storage = storage
            sender.resource.holder = holder
            return True
        except Exception as err:
            cls._resource_list_len.value -= 1
            cls._bad_resource_list.append(sender.resource.idx)
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            cls.error(f"Fail to init accounts for resource {opkey}:{rid}, err({err}): {err_tb}")
            return False

    @staticmethod
    def _min_operator_balance_to_err():
        return MIN_OPERATOR_BALANCE_TO_ERR

    @staticmethod
    def _min_operator_balance_to_warn():
        return MIN_OPERATOR_BALANCE_TO_WARN

    @classmethod
    def _validate_operator_balance(cls, sender: NeonTxSender):
        # Validate operator's account has enough SOLs
        sol_balance = sender.solana.get_sol_balance(sender.resource.public_key())
        min_operator_balance_to_err = cls._min_operator_balance_to_err()
        rid = sender.resource.rid
        opkey = str(sender.resource.public_key())
        if sol_balance <= min_operator_balance_to_err:
            cls.error(f'Operator account {opkey}:{rid} has NOT enough SOLs; balance = {sol_balance}; ' +
                       f'min_operator_balance_to_err = {min_operator_balance_to_err}')
            raise RuntimeError('Not enough SOLs')

        min_operator_balance_to_warn = cls._min_operator_balance_to_warn()
        if sol_balance <= min_operator_balance_to_warn:
            cls.warning(f'Operator account {opkey}:{rid} SOLs are running out; balance = {sol_balance}; ' +
                         f'min_operator_balance_to_warn = {min_operator_balance_to_warn}; ' +
                         f'min_operator_balance_to_err = {min_operator_balance_to_err}; ')

    @classmethod
    def _create_ether_account(cls, sender: NeonTxSender) -> EthereumAddress:
        rid = sender.resource.rid
        opkey = str(sender.resource.public_key())

        ether_address = EthereumAddress.from_private_key(sender.resource.secret_key())
        solana_address = ether2program(ether_address)[0]

        account_info = sender.solana.get_account_info(solana_address)
        if account_info is not None:
            cls.debug(f"Use existing ether account {str(solana_address)} for resource {opkey}:{rid}")
            return ether_address

        stage = NeonCreateAccountTxStage(sender, {"address": ether_address})
        stage.balance = sender.solana.get_multiple_rent_exempt_balances_for_size([stage.size])[0]
        stage.build()

        cls.debug(f"Create new ether account {str(solana_address)} for resource {opkey}:{rid}")
        SolTxListSender(cls._s, [stage.tx], NeonCreateAccountTxStage.NAME).send(sender.resource.signer)

        return ether_address

    @classmethod
    def _create_perm_accounts(cls, seed_list, sender: NeonTxSender):
        rid = sender.resource.rid
        opkey = str(sender.resource.public_key())

        tx = TransactionWithComputeBudget()
        tx_name_list = set()

        stage_list = [NeonCreatePermAccount(sender, seed, STORAGE_SIZE) for seed in seed_list]
        account_list = [s.sol_account for s in stage_list]
        info_list = sender.solana.get_account_info_list(account_list)
        balance = sender.solana.get_multiple_rent_exempt_balances_for_size([STORAGE_SIZE])[0]
        for idx, account, stage in zip(range(len(seed_list)), info_list, stage_list):
            if not account:
                cls.debug(f"Create new accounts for resource {opkey}:{rid}")
                stage.balance = balance
                stage.build()
                tx_name_list.add(stage.NAME)
                tx.add(stage.tx)
                continue
            elif account.lamports < balance:
                raise RuntimeError(f"insufficient balance of {str(stage.sol_account)}")
            elif PublicKey(account.owner) != PublicKey(EVM_LOADER_ID):
                raise RuntimeError(f"wrong owner for: {str(stage.sol_account)}")
            elif idx != 0:
                continue

            if account.tag == ACTIVE_STORAGE_TAG:
                cls.debug(f"Cancel transaction in {str(stage.sol_account)} for resource {opkey}:{rid}")
                cancel_stage = NeonCancelTxStage(sender, stage.sol_account)
                cancel_stage.build()
                tx_name_list.add(cancel_stage.NAME)
                tx.add(cancel_stage.tx)
            elif account.tag not in (FINALIZED_STORAGE_TAG, EMPTY_STORAGE_TAG):
                raise RuntimeError(f"not empty, not finalized: {str(stage.sol_account)}")

        if len(tx_name_list):
            SolTxListSender(sender, [tx], ' + '.join(tx_name_list)).send(sender.resource.signer)
        else:
            cls.debug(f"Use existing accounts for resource {opkey}:{rid}")
        return account_list

    @classmethod
    def get_resource_info(cls, idx: OperatorResourceId) -> OperatorResourceInfo:
        return cls._resource_list[idx]

    @classmethod
    def free_resource_info(cls, idx):
        cls._free_resource_list.append(idx)


@logged_group("neon.MemPool")
class NeonCreatePermAccount(NeonCreateAccountWithSeedStage, abc.ABC):
    NAME = 'createPermAccount'

    def __init__(self, sender, seed_base: bytes, size: int):
        NeonCreateAccountWithSeedStage.__init__(self, sender)
        self._seed_base = seed_base
        self.size = size
        self._init_sol_account()

    def _init_sol_account(self):
        assert len(self._seed_base) > 0
        seed = sha3.keccak_256(self._seed_base).hexdigest()[:32]
        self._seed = bytes(seed, 'utf8')
        self.sol_account = accountWithSeed(self.s.operator_key, self._seed)

    def build(self):
        assert self._is_empty()

        self.debug(f'Create perm account {self.sol_account}')
        self.tx.add(self._create_account_with_seed())
