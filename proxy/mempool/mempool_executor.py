import asyncio
import multiprocessing as mp
import socket

from logged_groups import logged_group, logging_context

from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.config import IConfig
from ..common_neon.utils import PipePickableDataSrv, PickableDataServerUser, Any
from ..common_neon.config import Config
from ..memdb.memdb import MemDB

from .transaction_sender import NeonTxSender
from .operator_resource_list import OperatorResourceList
from .mempool_api import MemPoolRequest, MemPoolResult, MemPoolResultCode


@logged_group("neon.MemPool")
class MPExecutor(mp.Process, PickableDataServerUser):

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

    def execute_neon_tx(self, mempool_request: MemPoolRequest):
        with logging_context(req_id=mempool_request.req_id, exectr=self._id):
            try:
                self.execute_neon_tx_impl(mempool_request)
            except Exception as err:
                self.error(f"Failed to execute neon_tx: {err}")
                return MemPoolResult(MemPoolResultCode.Unspecified, None)
            return MemPoolResult(MemPoolResultCode.Done, None)

    def execute_neon_tx_impl(self, mempool_tx_cfg: MemPoolRequest):
        neon_tx = mempool_tx_cfg.neon_tx
        neon_tx_cfg = mempool_tx_cfg.neon_tx_exec_cfg
        emulating_result = mempool_tx_cfg.emulating_result
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
