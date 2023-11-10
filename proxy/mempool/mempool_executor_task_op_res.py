import logging
from typing import List

from .mempool_api import (
    MPOpResGetListRequest, MPOpResGetListResult,
    MPOpResInitRequest, MPOpResInitResult, MPOpResInitResultCode
)
from .mempool_executor_task_base import MPExecutorBaseTask

from ..common_neon.config import Config
from ..common_neon.constants import EVM_PROGRAM_ID
from ..common_neon.evm_config import EVMConfig
from ..common_neon.solana_tx import SolPubKey
from ..common_neon.address import NeonAddress
from ..common_neon.errors import BadResourceError, RescheduleError, StuckTxError
from ..common_neon.neon_instruction import NeonIxBuilder

from ..common_neon.neon_tx_stages import (
    NeonCreateAccountTxStage, NeonCreateHolderAccountStage, NeonDeleteHolderAccountStage,
    NeonTxStage
)

from ..common_neon.operator_resource_info import OpResInfo, OpResInfoBuilder
from ..common_neon.operator_secret_mng import OpSecretMng
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx_list_sender import SolTxListSender

from ..neon_core_api.neon_client_base import NeonClientBase
from ..neon_core_api.neon_layouts import NeonAccountStatus, HolderStatus

from ..statistic.data import NeonOpResListData


LOG = logging.getLogger(__name__)


class OpResInit:
    def __init__(self, config: Config, solana: SolInteractor, neon_client: NeonClientBase):
        self._config = config
        self._solana = solana
        self._neon_client = neon_client

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
        for neon_acct in resource.neon_account_dict.values():
            neon_addr_str = f'{neon_acct.neon_address.checksum_address}:{neon_acct.chain_id}'

            if neon_acct.status == NeonAccountStatus.Ok:
                continue

            sol_addr = neon_acct.solana_address
            LOG.debug(f'Create neon account {str(sol_addr)}({neon_addr_str}) for resource {resource}')
            stage = NeonCreateAccountTxStage(builder, neon_acct)
            self._execute_stage(stage, resource)

    def _create_holder_account(self, builder: NeonIxBuilder, resource: OpResInfo) -> None:
        holder_address = str(resource.holder_account)
        holder_info = self._neon_client.get_holder_account_info(resource.holder_account)
        size = self._config.holder_size
        balance = self._solana.get_rent_exempt_balance_for_size(size)

        if holder_info.status == HolderStatus.Empty:
            LOG.debug(f'Create account {holder_address} for resource {resource}')
            stage = NeonCreateHolderAccountStage(builder, resource.holder_account, resource.holder_seed, size, balance)
            self._execute_stage(stage, resource)

        elif holder_info.data_size != size:
            LOG.debug(f'Resize account {holder_address} (size: {holder_info.data_size}) for resource {resource}')
            self._recreate_holder(builder, resource, balance)

        elif holder_info.status == HolderStatus.Active:
            raise StuckTxError(holder_info.neon_tx_sig, holder_info.chain_id, holder_address)

        elif holder_info.status not in {HolderStatus.Finalized, HolderStatus.Holder}:
            LOG.debug(f'Wrong tag {holder_info.status} of {holder_address} for resource {resource}')
            self._recreate_holder(builder, resource, size)

        else:
            LOG.debug(f'Use account {str(holder_info.owner)} for resource {resource}')

    def _recreate_holder(self, builder: NeonIxBuilder, resource: OpResInfo, balance: int) -> None:
        size = self._config.holder_size
        del_stage = NeonDeleteHolderAccountStage(builder, resource.holder_account)
        new_stage = NeonCreateHolderAccountStage(builder, resource.holder_account, resource.holder_seed, size, balance)
        self._execute_stage(del_stage, resource)
        self._execute_stage(new_stage, resource)


class MPExecutorOpResTask(MPExecutorBaseTask):
    def get_op_res_list(self, mp_req: MPOpResGetListRequest) -> MPOpResGetListResult:
        evm_config = EVMConfig()
        evm_config.set_evm_config(mp_req.evm_config_data)
        try:
            secret_list = OpSecretMng(self._config).read_secret_list()
            builder = OpResInfoBuilder(self._config, self._core_api_client)
            key_info_list = builder.build_key_list(secret_list)

            sol_acct_list: List[SolPubKey] = list()
            neon_addr_list: List[NeonAddress] = list()

            for key_info in key_info_list:
                sol_acct_list.append(key_info.public_key)
                for neon_acct in key_info.neon_account_dict.values():
                    neon_addr_list.append(neon_acct.neon_address)

            stat = NeonOpResListData(
                sol_account_list=sol_acct_list,
                neon_address_list=neon_addr_list,
                token_info_list=list(evm_config.token_info_list)
            )
            self._stat_client.commit_op_res_list(stat)

            res_info_list = builder.build_resource_list(key_info_list)
            return MPOpResGetListResult(res_info_list=res_info_list)

        except BaseException as exc:
            LOG.error(f'Failed to read secret list', exc_info=exc)
            return MPOpResGetListResult(res_info_list=[])

    def init_op_res(self, mp_op_res_req: MPOpResInitRequest) -> MPOpResInitResult:
        EVMConfig().set_evm_config(mp_op_res_req.evm_config_data)
        resource = mp_op_res_req.res_info
        try:
            OpResInit(self._config, self._solana, self._core_api_client).init_resource(resource)
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
