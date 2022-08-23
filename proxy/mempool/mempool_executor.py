import asyncio
import multiprocessing as mp
import socket
import traceback


from logged_groups import logged_group, logging_context
from typing import Optional, Any
from neon_py.network import PipePickableDataSrv, IPickableDataServerUser

from ..common_neon.gas_price_calculator import GasPriceCalculator
from ..common_neon.errors import BadResourceError, BlockedAccountsError
from ..common_neon.errors import NodeBehindError, SolanaUnavailableError
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.config import IConfig
from ..common_neon.config import Config

from .transaction_sender import NeonTxSendStrategyExecutor
from .operator_resource_mng import ResourceInitializer, OperatorResourceInfo
from .mempool_api import MPTxRequest, MPTxResult, MPResultCode


@logged_group("neon.MemPool")
class MPExecutor(mp.Process, IPickableDataServerUser):

    def __init__(self, executor_id: int, srv_sock: socket.socket, config: IConfig):
        self.info(f"Initialize mempool_executor: {executor_id}")
        self._id = executor_id
        self._srv_sock = srv_sock
        self._config = config
        self.info(f"Config: {self._config}")
        self._event_loop: asyncio.BaseEventLoop
        self._solana_interactor: Optional[SolanaInteractor] = None
        self._gas_price_calculator: Optional[GasPriceCalculator] = None
        self._pickable_data_srv: Optional[PipePickableDataSrv] = None
        mp.Process.__init__(self)

    def _init_in_proc(self):
        self.info(f"Config: {self._config}")
        self._event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._event_loop)
        self._pickable_data_srv = PipePickableDataSrv(user=self, srv_sock=self._srv_sock)
        self._solana_interactor = SolanaInteractor(self._config.get_solana_url())

        self._init_gas_price_calculator()

    def _init_gas_price_calculator(self):
        solana_url = self._config.get_solana_url()
        pyth_solana_url = self._config.get_pyth_solana_url()
        pyth_solana_interactor = self._solana_interactor if solana_url == pyth_solana_url else SolanaInteractor(pyth_solana_url)
        pyth_mapping_account = self._config.get_pyth_mapping_account()
        self._gas_price_calculator = GasPriceCalculator(pyth_solana_interactor, pyth_mapping_account)
        self._gas_price_calculator.update_mapping()
        self._gas_price_calculator.try_update_gas_price()

    def execute_neon_tx(self, mp_tx_request: MPTxRequest, operator_resource_info: OperatorResourceInfo):
        with logging_context(req_id=mp_tx_request.req_id, exectr=self._id):
            try:
                if mp_tx_request.gas_price < self._gas_price_calculator.get_min_gas_price():
                    self.debug(f"Failed to execute neon_tx: {mp_tx_request.log_str}, got low gas price error")
                    return MPTxResult(MPResultCode.LowGasPrice, None)
                self.execute_neon_tx_impl(mp_tx_request, operator_resource_info)
            except BlockedAccountsError:
                self.debug(f"Failed to execute neon_tx: {mp_tx_request.log_str}, got blocked accounts result")
                return MPTxResult(MPResultCode.BlockedAccount, None)
            except BadResourceError:
                self.debug(f"Failed to execute neon_tx: {mp_tx_request.log_str}, got bad resource error")
                return MPTxResult(MPResultCode.BadResourceError, None)
            except NodeBehindError:
                self.debug(f"Failed to execute neon_tx: {mp_tx_request.log_str}, got node behind error")
                return MPTxResult(MPResultCode.SolanaUnavailable, None)
            except SolanaUnavailableError:
                self.debug(f"Failed to execute neon_tx: {mp_tx_request.log_str}, got solana unavailable error")
                return MPTxResult(MPResultCode.SolanaUnavailable, None)
            except Exception as err:
                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.error(f"Failed to execute neon_tx: {mp_tx_request.log_str}, got error: {err}: {err_tb}")
                return MPTxResult(MPResultCode.Unspecified, None)
            return MPTxResult(MPResultCode.Done, None)

    def execute_neon_tx_impl(self, mp_tx_request: MPTxRequest, operator_resource: OperatorResourceInfo):
        neon_tx = mp_tx_request.neon_tx
        neon_tx_exec_cfg = mp_tx_request.neon_tx_exec_cfg
        resource = operator_resource

        if not ResourceInitializer(self._config, self._solana_interactor).init_resource(resource):
            self.debug(f"Got bad resource error")
            raise BadResourceError()
        if neon_tx_exec_cfg is None:
            self.error("Failed to process mp_tx_request, neon_tx_exec_cfg is not set")
            return

        strategy_executor = NeonTxSendStrategyExecutor(self._solana_interactor, resource, neon_tx)
        strategy_executor.execute(neon_tx_exec_cfg)

    async def on_data_received(self, data: Any) -> Any:
        mp_tx_request, operator_resource_info = data
        return self.execute_neon_tx(mp_tx_request, operator_resource_info)

    def run(self) -> None:
        self._config = Config()
        self._init_in_proc()
        self._event_loop.run_forever()
