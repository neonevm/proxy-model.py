import os
import time
import logging
from solana.rpc.api import Client
from multiprocessing.dummy import Pool as ThreadPool
from typing import Dict, Union

try:
    from sql_dict_bin_key import SQLDictBinKey
    from sql_dict import SQLDict
except ImportError:
    from .sql_dict_bin_key import SQLDictBinKey
    from .sql_dict import SQLDict


PARALLEL_REQUESTS = int(os.environ.get("PARALLEL_REQUESTS", "2"))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

DEVNET_HISTORY_START = "7BdwyUQ61RUZP63HABJkbW66beLk22tdXnP69KsvQBJekCPVaHoJY47Rw68b3VV1UbQNHxX3uxUSLfiJrfy2bTn"
HISTORY_START = [DEVNET_HISTORY_START]


log_levels = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARN': logging.WARN,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'FATAL': logging.FATAL,
    'CRITICAL': logging.CRITICAL
}

class IndexerBase:
    def __init__(self,
                 solana_url,
                 evm_loader_id,
                 log_level,
                 start_slot):
        logger.setLevel(log_levels.get(log_level, logging.INFO))

        self.evm_loader_id = evm_loader_id
        self.client = Client(solana_url)
        self.transaction_receipts = SQLDictBinKey(tablename="known_transactions")
        self.last_slot = start_slot
        self.current_slot = 0
        self.counter_ = 0

        if len(self.transaction_receipts) > 0:
            self.min_known_tx = min(self.transaction_receipts)
            self.max_known_tx = max(self.transaction_receipts)
        else:
            self.min_known_tx = (0, None)
            self.max_known_tx = (0, None)

        self._move_data_from_old_table()


    def _move_data_from_old_table(self):
        if len(self.transaction_receipts) == 0:
            transaction_receipts_old = SQLDict(tablename="known_transactions")
            for signature, trx in transaction_receipts_old.iteritems():
                self._add_trx(signature, trx)


    def run(self):
        while (True):
            self.process_functions()
            time.sleep(1.0)


    def process_functions(self):
        logger.debug("Start indexing")
        self.gather_unknown_transactions()


    def gather_unknown_transactions(self):
        poll_txs = set()

        minimal_tx = None
        continue_flag = True
        current_slot = self.client.get_slot(commitment="confirmed")["result"]

        max_known_tx = self.max_known_tx

        counter = 0
        while (continue_flag):
            results = self._get_signatures(minimal_tx, self.max_known_tx[1])
            logger.debug("{:>3} get_signatures_for_address {}".format(counter, len(results)))
            counter += 1

            if len(results) == 0:
                logger.debug("len(results) == 0")
                break

            minimal_tx = results[-1]["signature"]
            max_tx = (results[0]["slot"], results[0]["signature"])
            max_known_tx = max(max_known_tx, max_tx)

            for tx in results:
                solana_signature = tx["signature"]
                slot = tx["slot"]
                slot_sig = (slot, solana_signature)

                if solana_signature in HISTORY_START:
                    logger.debug(solana_signature)
                    continue_flag = False
                    break

                if slot_sig not in self.transaction_receipts:
                    poll_txs.add(solana_signature)

        logger.debug("start getting receipts")
        pool = ThreadPool(PARALLEL_REQUESTS)
        pool.map(self._get_tx_receipts, poll_txs)

        self.current_slot = current_slot
        self.counter_ = 0
        logger.debug(max_known_tx)
        self.max_known_tx = max_known_tx


    def _get_signatures(self, before, until):
        opts: Dict[str, Union[int, str]] = {}
        if until is not None:
            opts["until"] = until
        if before is not None:
            opts["before"] = before
        opts["commitment"] = "confirmed"
        result = self.client._provider.make_request("getSignaturesForAddress", self.evm_loader_id, opts)
        return result['result']


    def _get_tx_receipts(self, solana_signature):
        # trx = None
        retry = True

        while retry:
            try:
                trx = self.client.get_confirmed_transaction(solana_signature)['result']
                self._add_trx(solana_signature, trx)
                retry = False
            except Exception as err:
                logger.debug(err)
                time.sleep(1)

        self.counter_ += 1
        if self.counter_ % 100 == 0:
            logger.debug(self.counter_)


    def _add_trx(self, solana_signature, trx):
        if trx is not None:
            add = False
            for instruction in trx['transaction']['message']['instructions']:
                if trx["transaction"]["message"]["accountKeys"][instruction["programIdIndex"]] == self.evm_loader_id:
                    add = True
            if add:
                logger.debug((trx['slot'], solana_signature))
                self.transaction_receipts[(trx['slot'], solana_signature)] = trx
        else:
            logger.debug(f"trx is None {solana_signature}")

