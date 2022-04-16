import multiprocessing as mp
import os
import signal
from multiprocessing.managers import BaseManager
from abc import ABC, abstractmethod
from logged_groups import logged_group

from ..common_neon.data import NeonTxData


class MemPoolServerUser(ABC):

    @abstractmethod
    def on_eth_send_raw_transaction(self, neon_tx_data: NeonTxData):
        """Gets neon_tx_data from the neon rpc api service worker"""


@logged_group("neon.MemPool")
class MemPoolServer(ABC):

    QUEUE_TIMEOUT_SEC = 0.4
    BREAK_PROC_INVOCATION = 0
    JOIN_PROC_TIMEOUT_SEC = 5

    def __init__(self, *, user: MemPoolServerUser, host: str, port: int):
        self._user = user
        self._port = port
        self._host = host
        self._timeout = self.QUEUE_TIMEOUT_SEC

        class MemPoolManager(BaseManager):
            pass

        MemPoolManager.register("MemPool", lambda: self._user)
        self._mempool_manager = MemPoolManager(address=(host, port), authkey=b'abracadabra')
        self._mempool_server = self._mempool_manager.get_server()
        self._mempool_server_process = mp.Process(target=self._mempool_server.serve_forever, name="mempool_listen_proc")

        pid = os.getpid()
        signal.signal(signal.SIGINT, lambda sif, frame: self.finish() if os.getpid() == pid else 0)

    def start(self):
        self.info(f"Start listen on: {self._port} at: {self._host}")
        self._mempool_server_process.start()

    def finish(self):
        self._mempool_server_process.terminate()
