import asyncio
import multiprocessing as mp
import socket

from logged_groups import logged_group, logging_context

from ..common_neon.solana_tx_list_sender import BlockedAccountsError
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.config import IConfig
from ..common_neon.utils import PipePickableDataSrv, IPickableDataServerUser, Any
from ..common_neon.config import Config
from ..memdb.memdb import MemDB

from .transaction_sender import NeonTxSender
from .operator_resource_list import OperatorResourceList
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
        self._solana: SolanaInteractor
        self._db: MemDB
        self._pickable_data_srv = None
        mp.Process.__init__(self)

    def _init_in_proc(self):
        self.info(f"Config: {self._config}")
        self._event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._event_loop)
        self._pickable_data_srv = PipePickableDataSrv(user=self, srv_sock=self._srv_sock)
        self._solana = SolanaInteractor(self._config.get_solana_url())
        self._db = MemDB(self._solana)

    def execute_neon_tx(self, mp_tx_request: MPTxRequest):
        with logging_context(req_id=mp_tx_request.req_id, exectr=self._id):
            try:
                self.execute_neon_tx_impl(mp_tx_request)
            except BlockedAccountsError as err:
                self.warning(f"Blocked accounts: {err.blocked_accounts}, send BlockedAccount result back to the MemPool")
                return MPTxResult(MPResultCode.BlockedAccount, err.blocked_accounts)
            except Exception as err:
                self.error(f"Failed to execute neon_tx: {err}")
                return MPTxResult(MPResultCode.Unspecified, None)
            return MPTxResult(MPResultCode.Done, None)

    def execute_neon_tx_impl(self, mp_tx_request: MPTxRequest):
        neon_tx = mp_tx_request.neon_tx
        neon_tx_cfg = mp_tx_request.neon_tx_exec_cfg
        emulating_result = mp_tx_request.emulating_result
        emv_step_count = self._config.get_evm_count()
        tx_sender = NeonTxSender(self._db, self._solana, neon_tx, steps=emv_step_count)
        with OperatorResourceList(tx_sender):
            tx_sender.execute(neon_tx_cfg, emulating_result)

    async def on_data_received(self, data: Any) -> Any:
        return self.execute_neon_tx(data)

    def run(self) -> None:
        self._config = Config()
        self._init_in_proc()
        self._event_loop.run_forever()
