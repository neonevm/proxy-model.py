from logged_groups import logged_group
from multiprocessing import Pool


@logged_group("neon.MemPool")
class MemPool:

    POOL_PROC_COUNT = 20

    def __init__(self):
        self._pool = Pool(processes=self.POOL_PROC_COUNT)

    def on_eth_send_raw_transaction(self, *, eth_trx_hash):
        self._pool.apply_async(func=self._on_eth_send_raw_transaction_impl, args=(eth_trx_hash,),
                               callback=self.on_eth_send_raw_transaction_callback, error_callback=self.error_callback)

    def error_callback(self, error):
        self.error("Failed to invoke on worker process: ", error)

    def on_eth_send_raw_transaction_callback(self, result):
        pass

    def _on_eth_send_raw_transaction_impl(self, eth_trx_hash):
        self.debug(f"Transaction is being processed on the worker: {eth_trx_hash}")

    def do_extras(self):
        pass

    def __getstate__(self):
        self_dict = self.__dict__.copy()
        del self_dict['_pool']
        return self_dict

    def __setstate__(self, state):
        self.__dict__.update(state)
