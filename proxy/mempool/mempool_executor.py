import asyncio
import multiprocessing as mp
import socket
import traceback


from logged_groups import logged_group, logging_context
from typing import Optional, Any, List, Dict, cast
from neon_py.network import PipePickableDataSrv, IPickableDataServerUser

from ..common_neon.gas_price_calculator import GasPriceCalculator
from ..common_neon.errors import BlockedAccountsError
from ..common_neon.errors import NodeBehindError, SolanaUnavailableError, NonceTooLowError, BadResourceError
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.address import EthereumAddress
from ..common_neon.config import Config
from ..common_neon.elf_params import ElfParams

from .transaction_sender_ctx import NeonTxSendCtx
from .transaction_sender import NeonTxSendStrategyExecutor

from .operator_resource_mng import OperatorResourceInfo, OperatorResourceInitializer
from .mempool_api import MPRequestType, MPRequest
from .mempool_api import MPTxExecRequest, MPTxExecResult, MPTxExecResultCode
from .mempool_api import MPGasPriceResult
from .mempool_api import MPSenderTxCntRequest, MPSenderTxCntResult, MPSenderTxCntData
from .mempool_api import MPOpResInitRequest, MPOpResInitResult, MPOpResInitResultCode


@logged_group("neon.MemPool")
class MPExecutor(mp.Process, IPickableDataServerUser):
    def __init__(self, executor_id: int, srv_sock: socket.socket, config: Config):
        self.info(f"Initialize mempool_executor: {executor_id}")
        self._id = executor_id
        self._srv_sock = srv_sock
        self._config = config
        self.info(f"Config: {self._config}")
        self._event_loop: asyncio.BaseEventLoop
        self._solana: Optional[SolanaInteractor] = None
        self._gas_price_calculator: Optional[GasPriceCalculator] = None
        self._pickable_data_srv: Optional[PipePickableDataSrv] = None
        mp.Process.__init__(self)

    def _init_in_proc(self):
        self.info(f"Config: {self._config}")
        self._event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._event_loop)
        self._pickable_data_srv = PipePickableDataSrv(user=self, srv_sock=self._srv_sock)
        self._solana = SolanaInteractor(self._config.solana_url)

        self._init_gas_price_calculator()

    def _on_exception(self, text: str, err: BaseException) -> None:
        err_tb = "".join(traceback.format_tb(err.__traceback__))
        self.error(f"{text}. Error: {err}, Traceback: {err_tb}")

    def _init_gas_price_calculator(self):
        self._gas_price_calculator = GasPriceCalculator(SolanaInteractor(self._config.pyth_solana_url), self._config)
        self._update_gas_price_calculator()

    def _update_gas_price_calculator(self):
        if not self._gas_price_calculator.has_price():
            self._gas_price_calculator.update_mapping()
        if self._gas_price_calculator.has_price():
            self._gas_price_calculator.update_gas_price()

    def calc_gas_price(self) -> Optional[MPGasPriceResult]:
        self._update_gas_price_calculator()
        if not self._gas_price_calculator.is_valid():
            return None
        return MPGasPriceResult(
            suggested_gas_price=self._gas_price_calculator.suggested_gas_price,
            min_gas_price=self._gas_price_calculator.min_gas_price
        )

    def read_elf_param_dict(self) -> Optional[Dict[str, str]]:
        try:
            elf_params = ElfParams()
            elf_params.read_elf_param_dict_from_net()
            return elf_params.elf_param_dict
        except Exception as e:
            self._on_exception('Fail to read elf params', e)
            return None

    def get_state_tx_cnt(self, mp_state_req: MPSenderTxCntRequest) -> MPSenderTxCntResult:
        neon_address_list = [EthereumAddress(sender) for sender in mp_state_req.sender_list]
        neon_account_list = self._solana.get_neon_account_info_list(neon_address_list)

        state_tx_cnt_list: List[MPSenderTxCntData] = []
        for address, neon_account in zip(mp_state_req.sender_list, neon_account_list):
            data = MPSenderTxCntData(address, neon_account.tx_count if neon_account is not None else 0)
            state_tx_cnt_list.append(data)
        return MPSenderTxCntResult(sender_tx_cnt_list=state_tx_cnt_list)

    def init_operator_resource(self, mp_op_res_req: MPOpResInitRequest) -> MPOpResInitResult:
        ElfParams().set_elf_param_dict(mp_op_res_req.elf_param_dict)
        resource = OperatorResourceInfo.from_ident(mp_op_res_req.resource_ident)
        try:
            OperatorResourceInitializer(self._config, self._solana).init_resource(resource)
            return MPOpResInitResult(code=MPOpResInitResultCode.Success)
        except Exception as err:
            self._on_exception(f"Failed to init operator resource tx {resource}.", err)
            return MPOpResInitResult(code=MPOpResInitResultCode.Failed)

    def execute_neon_tx(self, mp_tx_req: MPTxExecRequest):
        neon_tx_exec_cfg = mp_tx_req.neon_tx_exec_cfg
        try:
            assert neon_tx_exec_cfg is not None
            self.execute_neon_tx_impl(mp_tx_req)
        except BlockedAccountsError:
            self.debug(f"Failed to execute tx {mp_tx_req.signature}, got blocked accounts result")
            return MPTxExecResult(MPTxExecResultCode.BlockedAccount, neon_tx_exec_cfg)
        except NodeBehindError:
            self.debug(f"Failed to execute tx {mp_tx_req.signature}, got node behind error")
            return MPTxExecResult(MPTxExecResultCode.NodeBehind, neon_tx_exec_cfg)
        except SolanaUnavailableError:
            self.debug(f"Failed to execute tx {mp_tx_req.signature}, got solana unavailable error")
            return MPTxExecResult(MPTxExecResultCode.SolanaUnavailable, neon_tx_exec_cfg)
        except NonceTooLowError:
            self.debug(f"Failed to execute tx {mp_tx_req.signature}, got nonce too low error")
            return MPTxExecResult(MPTxExecResultCode.NonceTooLow, neon_tx_exec_cfg)
        except BadResourceError as e:
            self.debug(f"Failed to execute tx {mp_tx_req.signature}, got bad resource error {str(e)}")
            return MPTxExecResult(MPTxExecResultCode.BadResource, neon_tx_exec_cfg)
        except Exception as err:
            self._on_exception(f"Failed to execute tx {mp_tx_req.signature}.", err)
            return MPTxExecResult(MPTxExecResultCode.Unspecified, neon_tx_exec_cfg)
        return MPTxExecResult(MPTxExecResultCode.Done, neon_tx_exec_cfg)

    def execute_neon_tx_impl(self, mp_tx_req: MPTxExecRequest):
        ElfParams().set_elf_param_dict(mp_tx_req.elf_param_dict)

        resource = OperatorResourceInfo.from_ident(mp_tx_req.resource_ident)

        neon_tx = mp_tx_req.neon_tx
        neon_tx_exec_cfg = mp_tx_req.neon_tx_exec_cfg
        strategy_ctx = NeonTxSendCtx(self._config, self._solana, resource, neon_tx, neon_tx_exec_cfg)
        strategy_executor = NeonTxSendStrategyExecutor(strategy_ctx)
        strategy_executor.execute()

    async def on_data_received(self, data: Any) -> Any:
        mp_req = cast(MPRequest, data)
        with logging_context(req_id=mp_req.req_id, exectr=self._id):
            if mp_req.type == MPRequestType.SendTransaction:
                mp_tx_req = cast(MPTxExecRequest, data)
                return self.execute_neon_tx(mp_tx_req)
            elif mp_req.type == MPRequestType.GetGasPrice:
                return self.calc_gas_price()
            elif mp_req.type == MPRequestType.GetElfParamDict:
                return self.read_elf_param_dict()
            elif mp_req.type == MPRequestType.GetStateTxCnt:
                mp_state_req = cast(MPSenderTxCntRequest, data)
                return self.get_state_tx_cnt(mp_state_req)
            elif mp_req.type == MPRequestType.InitOperatorResource:
                mp_op_res_req = cast(MPOpResInitRequest, data)
                return self.init_operator_resource(mp_op_res_req)
            self.error(f"Failed to process mp_request, unknown type: {mp_req.type}")
        return None

    def run(self) -> None:
        self._config = Config()
        self._init_in_proc()
        self._event_loop.run_forever()
