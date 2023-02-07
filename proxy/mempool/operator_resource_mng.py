from __future__ import annotations

import math
import dataclasses

import logging
from datetime import datetime
from typing import Optional, List, Dict, Deque, Set, Union, cast
from collections import deque

from .neon_tx_stages import NeonCreateAccountTxStage, NeonCreateHolderAccountStage, NeonDeleteHolderAccountStage
from .neon_tx_stages import NeonTxStage

from ..common_neon.address import NeonAddress, neon_2program, perm_account_seed, account_with_seed
from ..common_neon.cancel_transaction_executor import CancelTxExecutor
from ..common_neon.config import Config
from ..common_neon.constants import ACTIVE_HOLDER_TAG, FINALIZED_HOLDER_TAG, HOLDER_TAG
from ..common_neon.errors import BadResourceError
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx import SolPubKey, SolAccount
from ..common_neon.solana_tx_list_sender import SolTxListSender

from ..mempool.mempool_api import OpResIdent

from ..statistic.data import NeonOpResStatData
from ..statistic.proxy_client import ProxyStatClient


LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class OpResInfo:
    ident: OpResIdent
    signer: SolAccount

    holder: SolPubKey
    holder_seed: bytes

    neon_address: NeonAddress

    @staticmethod
    def from_ident(ident: OpResIdent) -> OpResInfo:
        signer = SolAccount.from_seed(ident.private_key)
        assert ident.public_key == str(signer.pubkey())

        holder_seed = perm_account_seed(b'holder-', ident.res_id)
        holder = account_with_seed(signer.pubkey(), holder_seed)
        neon_address = NeonAddress.from_private_key(signer.secret())

        return OpResInfo(ident=ident, signer=signer, holder=holder, holder_seed=holder_seed, neon_address=neon_address)

    def __str__(self) -> str:
        return str(self.ident)

    @property
    def public_key(self) -> SolPubKey:
        return self.signer.pubkey()

    @property
    def secret_key(self) -> bytes:
        return self.signer.secret()


class OpResInit:
    def __init__(self, config: Config, solana: SolInteractor):
        self._config = config
        self._solana = solana

    def init_resource(self, resource: OpResInfo):
        LOG.debug(f'Rechecking of accounts for resource {resource}')

        try:
            self._validate_operator_balance(resource)

            builder = NeonIxBuilder(resource.public_key)
            self._create_holder_account(builder, resource)
            self._create_neon_account(builder, resource)
        except BadResourceError:
            raise
        except BaseException as exc:
            LOG.error(f'Fail to init accounts for resource {resource}.', exc_info=exc)
            raise BadResourceError(exc)

    def _validate_operator_balance(self, resource: OpResInfo) -> None:
        # Validate operator's account has enough SOLs
        sol_balance = self._solana.get_sol_balance(resource.public_key)
        min_operator_balance_to_err = self._config.min_operator_balance_to_err
        if sol_balance <= min_operator_balance_to_err:
            LOG.error(
                f'Operator account {resource} has NOT enough SOLs; balance = {sol_balance}; ' +
                f'min_operator_balance_to_err = {min_operator_balance_to_err}'
            )
            raise BadResourceError(f'Not enough SOLs on the resource {resource}')

        min_operator_balance_to_warn = self._config.min_operator_balance_to_warn
        if sol_balance <= min_operator_balance_to_warn:
            LOG.warning(
                f'Operator account {resource} SOLs are running out; balance = {sol_balance}; ' +
                f'min_operator_balance_to_warn = {min_operator_balance_to_warn}; ' +
                f'min_operator_balance_to_err = {min_operator_balance_to_err}; '
            )

    def _execute_stage(self, stage: NeonTxStage, resource: OpResInfo) -> None:
        stage.build()
        tx_sender = SolTxListSender(self._config, self._solana, resource.signer)
        tx_sender.send([stage.tx])

    def _create_neon_account(self, builder: NeonIxBuilder, resource: OpResInfo):
        solana_address = neon_2program(resource.neon_address)[0]

        account_info = self._solana.get_account_info(solana_address)
        if account_info is not None:
            LOG.debug(f"Use neon account {str(solana_address)}({str(resource.neon_address)}) for resource {resource}")
            return []

        LOG.debug(f"Create neon account {str(solana_address)}({str(resource.neon_address)}) for resource {resource}")
        stage = NeonCreateAccountTxStage(builder, {"address": resource.neon_address})
        stage.set_balance(self._solana.get_multiple_rent_exempt_balances_for_size([stage.size])[0])
        self._execute_stage(stage, resource)

    def _create_holder_account(self, builder: NeonIxBuilder, resource: OpResInfo) -> None:
        holder_address = str(resource.holder)
        holder_info = self._solana.get_account_info(resource.holder)
        size = self._config.holder_size
        balance = self._solana.get_multiple_rent_exempt_balances_for_size([size])[0]

        if holder_info is None:
            LOG.debug(f"Create account {holder_address} for resource {resource}")
            self._execute_stage(NeonCreateHolderAccountStage(builder, resource.holder_seed, size, balance), resource)
        elif holder_info.lamports < balance:
            LOG.debug(f"Resize account {holder_address} for resource {resource}")
            self._recreate_holder(builder, resource, balance)
        elif holder_info.owner != self._config.evm_loader_id:
            raise BadResourceError(f'Wrong owner of {str(holder_info.owner)} for resource {resource}')
        elif holder_info.tag == ACTIVE_HOLDER_TAG:
            LOG.debug(f"Cancel transaction in {str(resource.holder)} for resource {resource}")
            self._unlock_storage_account(resource)
        elif holder_info.tag not in (FINALIZED_HOLDER_TAG, HOLDER_TAG):
            LOG.debug(f"Wrong tag {holder_info.tag} of {holder_address} for resource {resource}")
            self._recreate_holder(builder, resource, size)
        else:
            LOG.debug(f"Use account {str(holder_info.owner)} for resource {resource}")

    def _recreate_holder(self, builder: NeonIxBuilder, resource: OpResInfo, balance: int) -> None:
        size = self._config.holder_size
        self._execute_stage(NeonDeleteHolderAccountStage(builder, resource.holder_seed), resource)
        self._execute_stage(NeonCreateHolderAccountStage(builder, resource.holder_seed, size, balance), resource)

    def _unlock_storage_account(self, resource: OpResInfo) -> None:
        holder_info = self._solana.get_holder_account_info(resource.holder)
        cancel_tx_executor = CancelTxExecutor(self._config, self._solana, resource.signer)
        cancel_tx_executor.add_blocked_holder_account(holder_info)
        cancel_tx_executor.execute_tx_list()


@dataclasses.dataclass(frozen=True)
class OpResUsedTime:
    ident: OpResIdent

    last_used_time: int = 0
    used_cnt: int = 0
    neon_sig: str = ''

    def __str__(self) -> str:
        return str(self.ident)

    def __hash__(self) -> int:
        return hash(self.ident)

    def set_last_used_time(self, value: int) -> None:
        object.__setattr__(self, 'used_cnt', self.used_cnt + 1)
        object.__setattr__(self, 'last_used_time', value)

    def set_neon_sig(self, value: str) -> None:
        assert len(value) > 0
        object.__setattr__(self, 'neon_sig', value)

    def reset_neon_sig(self) -> None:
        object.__setattr__(self, 'neon_sig', '')

    def reset_used_cnt(self) -> None:
        object.__setattr__(self, 'used_cnt', 0)


class OpResIdentListBuilder:
    def __init__(self, config: Config):
        self._config = config

    def build_resource_list(self, secret_list: List[bytes]) -> List[OpResIdent]:
        ident_set: Set[OpResIdent] = set()

        stop_perm_account_id = self._config.perm_account_id + self._config.perm_account_limit
        for res_id in range(self._config.perm_account_id, stop_perm_account_id):
            for ident in secret_list:
                sol_account = SolAccount.from_seed(ident)
                ident = OpResIdent(
                    public_key=str(sol_account.pubkey()),
                    private_key=sol_account.secret(),
                    res_id=res_id
                )
                ident_set.add(ident)

        return list(ident_set)


class OpResMng:
    def __init__(self, config: Config, stat_client: ProxyStatClient):
        self._secret_list: List[bytes] = []
        self._res_ident_set: Set[OpResIdent] = set()
        self._free_res_ident_list: Deque[OpResUsedTime] = deque()
        self._used_res_ident_dict: Dict[str, OpResUsedTime] = dict()
        self._disabled_res_ident_list: Deque[OpResIdent] = deque()
        self._checked_res_ident_set: Set[OpResIdent] = set()
        self._stat_client = stat_client
        self._config = config
        self._last_check_time = 0

    def init_resource_list(self, res_ident_list: List[OpResIdent]) -> None:
        old_res_cnt = self.resource_cnt

        new_ident_set: Set[OpResIdent] = set(res_ident_list)
        rm_ident_set: Set[OpResIdent] = self._res_ident_set.difference(new_ident_set)
        add_ident_set: Set[OpResIdent] = new_ident_set.difference(self._res_ident_set)

        if (len(rm_ident_set) == 0) and (len(add_ident_set) == 0):
            LOG.debug(f'Same resource list')
            return

        self._res_ident_set = new_ident_set
        self._free_res_ident_list = deque([res for res in self._free_res_ident_list if res.ident not in rm_ident_set])
        self._disabled_res_ident_list = deque([res for res in self._disabled_res_ident_list if res not in rm_ident_set])
        self._checked_res_ident_set = {res for res in self._checked_res_ident_set if res not in rm_ident_set}

        for res in rm_ident_set:
            LOG.debug(f'Remove resource {res}')
        for res in add_ident_set:
            LOG.debug(f'Add resource {res}')
            self._disabled_res_ident_list.append(res)

        self._secret_list: List[bytes] = [pk for pk in {res.private_key for res in self._res_ident_set}]

        if old_res_cnt != self.resource_cnt != 0:
            LOG.debug(f'Change number of resources from {old_res_cnt} to {self.resource_cnt}')
        self._commit_stat()

    @property
    def resource_cnt(self) -> int:
        return len(self._res_ident_set)

    @staticmethod
    def _get_current_time() -> int:
        return math.ceil(datetime.now().timestamp())

    def _get_resource_impl(self, neon_sig: str) -> Optional[OpResUsedTime]:
        res_used_time = self._used_res_ident_dict.get(neon_sig, None)
        if res_used_time is not None:
            LOG.debug(f'Reuse resource {res_used_time} for tx {neon_sig}')
            return res_used_time

        if len(self._free_res_ident_list) > 0:
            res_used_time = self._free_res_ident_list.popleft()
            self._used_res_ident_dict[neon_sig] = res_used_time
            res_used_time.set_neon_sig(neon_sig)
            LOG.debug(f'Use resource {res_used_time} for tx {neon_sig}')
            self._commit_stat()
            return res_used_time

        return None

    def _pop_used_resource(self, neon_sig: str) -> Optional[OpResUsedTime]:
        res_used_time = self._used_res_ident_dict.pop(neon_sig, None)
        if (res_used_time is None) or (res_used_time.ident not in self._res_ident_set):
            LOG.debug(f'Skip resource {str(res_used_time)} for tx {neon_sig}')
            return None

        self._commit_stat()

        res_used_time.reset_neon_sig()
        return res_used_time

    def get_resource(self, neon_sig: str) -> Optional[OpResIdent]:
        res_used_time = self._get_resource_impl(neon_sig)
        if res_used_time is None:
            return None

        now = self._get_current_time()
        res_used_time.set_last_used_time(now)

        return res_used_time.ident

    def update_resource(self, neon_sig: str) -> None:
        res_used_time = self._used_res_ident_dict.get(neon_sig, None)
        if res_used_time is not None:
            LOG.debug(f'Update time for resource {res_used_time}')
            now = self._get_current_time()
            res_used_time.set_last_used_time(now)

    def release_resource(self, neon_sig: str) -> Optional[OpResIdent]:
        res_used_time = self._pop_used_resource(neon_sig)
        if res_used_time is None:
            return None

        recheck_cnt = self._config.recheck_resource_after_uses_cnt
        if res_used_time.used_cnt > recheck_cnt:
            LOG.debug(f'Recheck resource {res_used_time} by counter')
            self._disabled_res_ident_list.append(res_used_time.ident)
        else:
            LOG.debug(f'Release resource {res_used_time}')
            self._free_res_ident_list.append(res_used_time)
        self._commit_stat()

        return res_used_time.ident

    def disable_resource(self, ident_or_sig: Union[OpResIdent, str]) -> None:
        if isinstance(ident_or_sig, str):
            res_time: Optional[OpResUsedTime] = self._pop_used_resource(cast(str, ident_or_sig))
            if res_time is None:
                return
            ident = res_time.ident
        elif isinstance(ident_or_sig, OpResIdent):
            ident = cast(OpResIdent, ident_or_sig)
        else:
            assert False, f'Wrong type {type(ident_or_sig)} of ident_or_sig'

        LOG.debug(f'Disable resource {ident}')
        self._checked_res_ident_set.discard(ident)
        self._disabled_res_ident_list.append(ident)
        self._commit_stat()

    def enable_resource(self, ident: OpResIdent) -> None:
        if ident not in self._res_ident_set:
            LOG.debug(f'Skip resource {ident}')
            return

        LOG.debug(f'Enable resource {ident}')
        self._checked_res_ident_set.discard(ident)
        self._free_res_ident_list.append(OpResUsedTime(ident=ident))
        self._commit_stat()

    def get_secret_list(self) -> List[bytes]:
        return self._secret_list

    def get_disabled_resource(self) -> Optional[OpResIdent]:
        now = self._get_current_time()
        recheck_sec = self._config.recheck_used_resource_sec
        check_time = now - recheck_sec

        if self._last_check_time < check_time:
            self._last_check_time = now
            for neon_sig, res_used_time in list(self._used_res_ident_dict.items()):
                if res_used_time.last_used_time < check_time:
                    res_used_time = self._pop_used_resource(neon_sig)
                    if res_used_time is not None:
                        LOG.debug(f'Recheck resource {res_used_time} by time usage')
                        self._disabled_res_ident_list.append(res_used_time.ident)

        if len(self._disabled_res_ident_list) == 0:
            return None

        ident = self._disabled_res_ident_list.popleft()
        LOG.debug(f'Recheck resource {ident}')
        self._checked_res_ident_set.add(ident)

        self._commit_stat()
        return ident

    def _commit_stat(self) -> None:
        stat = NeonOpResStatData(
            secret_cnt=len(self._secret_list),
            total_res_cnt=len(self._res_ident_set),
            free_res_cnt=len(self._free_res_ident_list),
            used_res_cnt=len(self._used_res_ident_dict),
            disabled_res_cnt=len(self._disabled_res_ident_list)
        )
        self._stat_client.commit_op_res_stat(stat)
