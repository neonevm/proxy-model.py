from ..common_neon.base_process import BaseProcess
from logged_groups import logged_group
from multiprocessing.managers import BaseManager
import multiprocessing as mp


@logged_group("neon.Proxy")
class MemPoolService:

    def __init__(self):
        self._queue = mp.Queue()

        class MemPoolQueueManager(BaseManager):
            pass
        MemPoolQueueManager.register("get_queue", callable=lambda: self._queue)
        self.queue_manager = MemPoolQueueManager(address=('', 9091), authkey=b'abracadabra')

    def start(self):
        self.debug("Starting queue server")
        mempool_server = self.queue_manager.get_server()
        mempool_server.serve_forever()


    # def on_eth_send_raw_transaction(self, trx):
    #     self.debug(f"Got raw transaction to send: {trx}")
    #
    # def do_extras(self):
    #     self.debug("Do extras")
