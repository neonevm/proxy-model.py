import asyncio
import multiprocessing as mp
import socket
import traceback

from logged_groups import logged_group, logging_context
from typing import Optional, Any, List, cast
from neon_py.network import PipePickableDataSrv, IPickableDataServerUser

from ..common_neon.gas_price_calculator import GasPriceCalculator
from ..common_neon.errors import BlockedAccountsError, NodeBehindError, SolanaUnavailableError, NonceTooLowError
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.address import EthereumAddress
from ..common_neon.config import IConfig
from ..common_neon.config import Config

from .transaction_sender_ctx import NeonTxSendCtx
from .transaction_sender import NeonTxSendStrategyExecutor
from .operator_resource_list import OperatorResourceList
from .mempool_api import MPRequestType, MPRequest, MPTxRequest, MPTxExecResult, MPTxExecResultCode, MPGasPriceResult
from .mempool_api import MPSenderTxCntRequest, MPSenderTxCntResult, MPSenderTxCntData


@logged_group("neon.MemPool")
class MPExecutor(mp.Process, IPickableDataServerUser):
    def __init__(self, executor_id: int, srv_sock: socket.socket, config: IConfig):
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
        self._solana = SolanaInteractor(self._config.get_solana_url())

        self._init_gas_price_calculator()

    def _init_gas_price_calculator(self):
        solana_url = self._config.get_solana_url()
        pyth_solana_url = self._config.get_pyth_solana_url()
        pyth_solana = self._solana if solana_url == pyth_solana_url else SolanaInteractor(pyth_solana_url)
        pyth_mapping_account = self._config.get_pyth_mapping_account()
        self._gas_price_calculator = GasPriceCalculator(pyth_solana, pyth_mapping_account)
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
            suggested_gas_price=self._gas_price_calculator.get_suggested_gas_price(),
            min_gas_price=self._gas_price_calculator.get_min_gas_price()
        )

    def get_state_tx_cnt(self, mp_state_req: MPSenderTxCntRequest) -> MPSenderTxCntResult:
        neon_address_list = [EthereumAddress(sender) for sender in mp_state_req.sender_list]
        neon_account_list = self._solana.get_neon_account_info_list(neon_address_list)

        state_tx_cnt_list: List[MPSenderTxCntData] = []
        for address, neon_account in zip(mp_state_req.sender_list, neon_account_list):
            data = MPSenderTxCntData(address, neon_account.tx_count if neon_account is not None else 0)
            state_tx_cnt_list.append(data)
        return MPSenderTxCntResult(sender_tx_cnt_list=state_tx_cnt_list)

    def execute_neon_tx(self, mp_tx_request: MPTxRequest):
        with logging_context(req_id=mp_tx_request.req_id, exectr=self._id):
            try:
                self.execute_neon_tx_impl(mp_tx_request)
            except BlockedAccountsError:
                self.debug(f"Failed to execute neon_tx, got blocked accounts result")
                return MPTxExecResult(MPTxExecResultCode.BlockedAccount, mp_tx_request.neon_tx_exec_cfg)
            except NodeBehindError:
                self.debug(f"Failed to execute neon_tx, got node behind error")
                return MPTxExecResult(MPTxExecResultCode.SolanaUnavailable, mp_tx_request.neon_tx_exec_cfg)
            except SolanaUnavailableError:
                self.debug(f"Failed to execute neon_tx, got solana unavailable error")
                return MPTxExecResult(MPTxExecResultCode.SolanaUnavailable, mp_tx_request.neon_tx_exec_cfg)
            except NonceTooLowError:
                self.debug(f"Failed to execute neon_tx, got nonce too low error")
                return MPTxExecResult(MPTxExecResultCode.NonceTooLow, mp_tx_request.neon_tx_exec_cfg)
            except Exception as err:
                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.error(f"Failed to execute neon_tx, got error. Error: {err}. Traceback: {err_tb}")
                return MPTxExecResult(MPTxExecResultCode.Unspecified, mp_tx_request.neon_tx_exec_cfg)
            return MPTxExecResult(MPTxExecResultCode.Done, mp_tx_request.neon_tx_exec_cfg)

    def execute_neon_tx_impl(self, mp_tx_request: MPTxRequest):
        neon_tx = mp_tx_request.neon_tx
        neon_tx_exec_cfg = mp_tx_request.neon_tx_exec_cfg

        resource_list = OperatorResourceList(self._solana)
        resource = resource_list.get_available_resource_info()

        strategy_ctx = NeonTxSendCtx(self._solana, resource, neon_tx, neon_tx_exec_cfg)
        strategy_executor = NeonTxSendStrategyExecutor(strategy_ctx)
        try:
            strategy_executor.execute()
        finally:
            mp_tx_request.neon_tx_exec_cfg = strategy_ctx.neon_tx_exec_cfg
            resource_list.free_resource_info(resource)

    async def on_data_received(self, data: Any) -> Any:
        mp_req = cast(MPRequest, data)
        if mp_req.type == MPRequestType.SendTransaction:
            mp_tx_req = cast(MPTxRequest, data)
            return self.execute_neon_tx(mp_tx_req)
        elif mp_req.type == MPRequestType.GetGasPrice:
            return self.calc_gas_price()
        elif mp_req.type == MPRequestType.GetStateTxCnt:
            mp_state_req = cast(MPSenderTxCntRequest, data)
            return self.get_state_tx_cnt(mp_state_req)
        self.error(f"Failed to process mp_request, unknown type: {mp_req.type}")
        return None

    def run(self) -> None:
        self._config = Config()
        self._init_in_proc()
        self._event_loop.run_forever()
