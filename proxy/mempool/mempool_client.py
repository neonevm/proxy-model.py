from multiprocessing.managers import BaseManager
from logged_groups import logged_group


@logged_group("neon.Proxy")
class MemPoolClient:

    def __init__(self, host: str, port: int):

        self.info(f"Initialize MemPoolClient connecting to: {port} at: {host}")

        class MemPoolManager(BaseManager):
            def __init__(self):
                super(MemPoolManager, self).__init__(address=(host, port), authkey=b'abracadabra')
                self.register("MemPool")

        self._mempool_manager = MemPoolManager()
        self._mempool_manager.connect()
        self._mempool = self._mempool_manager.MemPool()

    def on_eth_send_raw_transaction(self, neon_tx_data):
        try:
            self._mempool.on_eth_send_raw_transaction(neon_tx_data)
        except BaseException as err:
            self.error(f"Failed to send raw transaction onto mempool: {err}")
            raise Exception("Failed to send to the mempool")
