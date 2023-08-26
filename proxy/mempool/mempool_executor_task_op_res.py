import logging
from typing import List

from .mempool_api import MPOpResGetListResult, MPOpResInitRequest, MPOpResInitResult, MPOpResInitResultCode
from .mempool_executor_task_base import MPExecutorBaseTask

from ..common_neon.address import neon_2program
from ..common_neon.config import Config
from ..common_neon.constants import ACTIVE_HOLDER_TAG, FINALIZED_HOLDER_TAG, HOLDER_TAG, EVM_PROGRAM_ID
from ..common_neon.elf_params import ElfParams
from ..common_neon.errors import BadResourceError, RescheduleError, StuckTxError
from ..common_neon.neon_instruction import NeonIxBuilder

from ..common_neon.neon_tx_stages import (
    NeonCreateAccountTxStage, NeonCreateHolderAccountStage, NeonDeleteHolderAccountStage,
    NeonTxStage
)

from ..common_neon.operator_resource_info import OpResInfo, OpResIdentListBuilder
from ..common_neon.operator_secret_mng import OpSecretMng
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx_list_sender import SolTxListSender

from ..statistic.data import NeonOpResListData
from ..statistic.proxy_client import ProxyStatClient


LOG = logging.getLogger(__name__)


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
        except (RescheduleError, StuckTxError):
            raise

        except BaseException as exc:
            LOG.error(f'Fail to init accounts for resource {resource}', exc_info=exc)
            raise BadResourceError(str(exc))

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
            LOG.debug(f'Use neon account {str(solana_address)}({str(resource.neon_address)}) for resource {resource}')
            return

        LOG.debug(f'Create neon account {str(solana_address)}({str(resource.neon_address)}) for resource {resource}')
        stage = NeonCreateAccountTxStage(builder, {'address': resource.neon_address})
        stage.set_balance(self._solana.get_multiple_rent_exempt_balances_for_size([stage.size])[0])
        self._execute_stage(stage, resource)

    def _create_holder_account(self, builder: NeonIxBuilder, resource: OpResInfo) -> None:
        holder_address = str(resource.holder_account)
        holder_info = self._solana.get_holder_account_info(resource.holder_account)
        size = self._config.holder_size
        balance = self._solana.get_multiple_rent_exempt_balances_for_size([size])[0]

        if holder_info is None:
            LOG.debug(f'Create account {holder_address} for resource {resource}')
            self._execute_stage(NeonCreateHolderAccountStage(builder, resource.holder_seed, size, balance), resource)

        elif (holder_info.lamports < balance) or (holder_info.data_size != size):
            LOG.debug(
                f'Resize account {holder_address} '
                f'(balance: {holder_info.lamports}, size: {holder_info.data_size}) '
                f'for resource {resource}'
            )
            self._recreate_holder(builder, resource, balance)

        elif holder_info.owner != EVM_PROGRAM_ID:
            raise BadResourceError(f'Wrong owner of {str(holder_info.owner)} for resource {resource}')

        elif holder_info.tag == ACTIVE_HOLDER_TAG:
            raise StuckTxError(holder_info.neon_tx_sig, holder_address)

        elif holder_info.tag not in {FINALIZED_HOLDER_TAG, HOLDER_TAG}:
            LOG.debug(f'Wrong tag {holder_info.tag} of {holder_address} for resource {resource}')
            self._recreate_holder(builder, resource, size)

        else:
            LOG.debug(f'Use account {str(holder_info.owner)} for resource {resource}')

    def _recreate_holder(self, builder: NeonIxBuilder, resource: OpResInfo, balance: int) -> None:
        size = self._config.holder_size
        self._execute_stage(NeonDeleteHolderAccountStage(builder, resource.holder_seed), resource)
        self._execute_stage(NeonCreateHolderAccountStage(builder, resource.holder_seed, size, balance), resource)


class MPExecutorOpResTask(MPExecutorBaseTask):
    def __init__(self, config: Config, solana: SolInteractor, stat_client: ProxyStatClient):
        super().__init__(config, solana)
        self._stat_client = stat_client

    def get_op_res_list(self) -> MPOpResGetListResult:
        try:
            secret_list = OpSecretMng(self._config).read_secret_list()
            res_ident_list = OpResIdentListBuilder(self._config).build_resource_list(secret_list)

            sol_account_list: List[str] = []
            neon_account_list: List[str] = []

            for res_ident in res_ident_list:
                op_info = OpResInfo.from_ident(res_ident)
                sol_account_list.append(str(op_info.public_key))
                neon_account_list.append(str(op_info.neon_address))

            stat = NeonOpResListData(
                sol_account_list=sol_account_list,
                neon_account_list=neon_account_list
            )
            self._stat_client.commit_op_res_list(stat)

            return MPOpResGetListResult(res_ident_list=res_ident_list)

        except BaseException as exc:
            LOG.error(f'Failed to read secret list', exc_info=exc)
            return MPOpResGetListResult(res_ident_list=[])

    def init_op_res(self, mp_op_res_req: MPOpResInitRequest) -> MPOpResInitResult:
        ElfParams().set_elf_param_dict(mp_op_res_req.elf_param_dict)
        resource = OpResInfo.from_ident(mp_op_res_req.res_ident)
        try:
            OpResInit(self._config, self._solana).init_resource(resource)
            return MPOpResInitResult(MPOpResInitResultCode.Success, None)

        except RescheduleError as exc:
            LOG.debug(f'Rescheduling init of operator resource {resource}: {str(exc)}')
            return MPOpResInitResult(MPOpResInitResultCode.Reschedule, None)

        except StuckTxError as exc:
            LOG.debug(str(exc))
            return MPOpResInitResult(MPOpResInitResultCode.StuckTx, exc)

        except BaseException as exc:
            LOG.error(f'Failed to init operator resource tx {resource}', exc_info=exc)
            return MPOpResInitResult(MPOpResInitResultCode.Failed, None)
