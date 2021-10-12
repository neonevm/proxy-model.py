import base58
import rlp
import json
import os
import time
import logging
from solana.rpc.api import Client
from multiprocessing.dummy import Pool as ThreadPool
from sqlitedict import SqliteDict
from typing import Dict, Union


try:
    from utils import check_error, get_trx_results, get_trx_receipts, LogDB, Canceller
except ImportError:
    from .utils import check_error, get_trx_results, get_trx_receipts, LogDB, Canceller


solana_url = os.environ.get("SOLANA_URL", "https://api.devnet.solana.com")
evm_loader_id = os.environ.get("EVM_LOADER", "eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU")
PARALLEL_REQUESTS = int(os.environ.get("PARALLEL_REQUESTS", "2"))


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

UPDATE_BLOCK_COUNT = PARALLEL_REQUESTS * 16

class HolderStruct:
    def __init__(self, storage_account):
        self.storage_account = storage_account
        self.data = bytearray(128*1024)
        self.count_written = 0
        self.max_written = 0


class ContinueStruct:
    def __init__(self, signature, results):
        self.signatures = [signature]
        self.results = results


class Indexer:
    def __init__(self):
        self.client = Client(solana_url)
        self.canceller = Canceller()
        self.logs_db = LogDB(filename="local.db")
        self.blocks_by_hash = SqliteDict(filename="local.db", tablename="solana_blocks_by_hash", autocommit=True)
        self.transaction_receipts = SqliteDict(filename="local.db", tablename="known_transactions", autocommit=True, encode=json.dumps, decode=json.loads)
        self.ethereum_trx = SqliteDict(filename="local.db", tablename="ethereum_transactions", autocommit=True, encode=json.dumps, decode=json.loads)
        self.eth_sol_trx = SqliteDict(filename="local.db", tablename="ethereum_solana_transactions", autocommit=True, encode=json.dumps, decode=json.loads)
        self.sol_eth_trx = SqliteDict(filename="local.db", tablename="solana_ethereum_transactions", autocommit=True, encode=json.dumps, decode=json.loads)
        self.constants = SqliteDict(filename="local.db", tablename="constants", autocommit=True)
        self.last_slot = 0
        self.current_slot = 0
        self.transaction_order = []
        if 'last_block' not in self.constants:
            self.constants['last_block'] = 0
        self.blocked_storages = set()
        self.counter_ = 0

    def run(self, loop = True):
        while (True):
            try:
                logger.debug("Start indexing")
                self.gather_unknown_transactions()
                logger.debug("Process receipts")
                self.process_receipts()
                logger.debug("Start getting blocks")
                self.gather_blocks()
                logger.debug("Unlock accounts")
                self.canceller.unlock_accounts(self.blocked_storages)
                self.blocked_storages.clear()
            except Exception as err:
                logger.debug("Got exception while indexing. Type(err):%s, Exception:%s", type(err), err)

            if loop:
                time.sleep(1)
            else:
                break

    def gather_unknown_transactions(self):
        poll_txs = set()
        ordered_txs = []

        minimal_tx = None
        continue_flag = True
        current_slot = self.client.get_slot(commitment="confirmed")["result"]
        maximum_slot = self.last_slot
        minimal_slot = current_slot

        percent = 0

        counter = 0
        while (continue_flag):
            opts: Dict[str, Union[int, str]] = {}
            if minimal_tx:
                opts["before"] = minimal_tx
            opts["commitment"] = "confirmed"
            result = self.client._provider.make_request("getSignaturesForAddress", evm_loader_id, opts)
            logger.debug("{:>3} get_signatures_for_address {}".format(counter, len(result["result"])))
            counter += 1

            if len(result["result"]) == 0:
                logger.debug("len(result['result']) == 0")
                break

            for tx in result["result"]:
                solana_signature = tx["signature"]
                slot = tx["slot"]

                if solana_signature == "7BdwyUQ61RUZP63HABJkbW66beLk22tdXnP69KsvQBJekCPVaHoJY47Rw68b3VV1UbQNHxX3uxUSLfiJrfy2bTn":
                    logger.debug(solana_signature)
                    continue_flag = False
                    break

                ordered_txs.append(solana_signature)

                if solana_signature not in self.transaction_receipts:
                    poll_txs.add(solana_signature)

                if slot < minimal_slot:
                    minimal_slot = slot
                    minimal_tx = solana_signature

                if slot > maximum_slot:
                    maximum_slot = slot

                if slot < self.last_slot:
                    continue_flag = False
                    break

        logger.debug("start getting receipts")
        pool = ThreadPool(PARALLEL_REQUESTS)
        pool.map(self.get_tx_receipts, poll_txs)

        if len(self.transaction_order):
            index = 0
            try:
                index = ordered_txs.index(self.transaction_order[0])
            except ValueError:
                self.transaction_order = ordered_txs + self.transaction_order
            else:
                self.transaction_order = ordered_txs[:index] + self.transaction_order
        else:
            self.transaction_order = ordered_txs

        self.last_slot = maximum_slot
        self.current_slot = current_slot

        self.counter_ = 0


    def get_tx_receipts(self, solana_signature):
        # trx = None
        retry = True

        while retry:
            try:
                trx = self.client.get_confirmed_transaction(solana_signature)['result']
                self.transaction_receipts[solana_signature] = trx
                retry = False
            except Exception as err:
                logger.debug(err)
                time.sleep(1)

        self.counter_ += 1
        if self.counter_ % 100 == 0:
            logger.debug(self.counter_)

        # return (solana_signature, trx)


    def process_receipts(self):
        counter = 0
        holder_table = {}
        continue_table = {}

        for signature in self.transaction_order:
            counter += 1

            if signature in self.sol_eth_trx:
                continue

            if signature in self.transaction_receipts:
                trx = self.transaction_receipts[signature]
                if trx is None:
                    logger.error("trx is None")
                    del self.transaction_receipts[signature]
                    continue
                if 'slot' not in trx:
                    logger.debug("\n{}".format(json.dumps(trx, indent=4, sort_keys=True)))
                    exit()
                slot = trx['slot']
                if trx['transaction']['message']['instructions'] is not None:
                    for instruction in trx['transaction']['message']['instructions']:
                        instruction_data = base58.b58decode(instruction['data'])

                        if check_error(trx):
                            continue

                        if instruction_data[0] == 0x00: # Write
                            # logger.debug("{:>10} {:>6} Write 0x{}".format(slot, counter, instruction_data[-20:].hex()))

                            write_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]

                            if write_account in holder_table:
                                storage_account = holder_table[write_account].storage_account
                                if storage_account in continue_table:
                                    continue_table[storage_account].signatures.append(signature)

                                offset = int.from_bytes(instruction_data[4:8], "little")
                                length = int.from_bytes(instruction_data[8:16], "little")
                                data = instruction_data[16:]

                                # logger.debug("WRITE offset {} length {}".format(offset, length))

                                if holder_table[write_account].max_written < (offset + length):
                                    holder_table[write_account].max_written = offset + length

                                for index in range(length):
                                    holder_table[write_account].data[1+offset+index] = data[index]
                                    holder_table[write_account].count_written += 1

                                if holder_table[write_account].max_written == holder_table[write_account].count_written:
                                    # logger.debug("WRITE {} {}".format(holder_table[write_account].max_written, holder_table[write_account].count_written))
                                    signature = holder_table[write_account].data[1:66]
                                    length = int.from_bytes(holder_table[write_account].data[66:74], "little")
                                    unsigned_msg = holder_table[write_account].data[74:74+length]

                                    try:
                                        (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, signature)
                                        if len(eth_trx) / 2 > holder_table[write_account].max_written:
                                            logger.debug("WRITE got {} exp {}".format(len(eth_trx), holder_table[write_account].max_written))
                                            continue

                                        if storage_account in continue_table:
                                            continue_result = continue_table[storage_account]

                                            self.submit_transaction(eth_trx, eth_signature, from_address, continue_result.results, continue_result.signatures)

                                            del continue_table[storage_account]
                                        else:
                                            logger.error("Storage not found")
                                            logger.error(eth_signature, "unknown")
                                            # raise

                                        del holder_table[write_account]
                                    except rlp.exceptions.RLPException:
                                        pass
                                    except Exception as err:
                                        if str(err).startswith("unhashable type"):
                                            pass
                                        elif str(err).startswith("unsupported operand type"):
                                            pass
                                        else:
                                            logger.debug("could not parse trx {}".format(err))
                                            raise

                        elif instruction_data[0] == 0x01: # Finalize
                            # logger.debug("{:>10} {:>6} Finalize 0x{}".format(slot, counter, instruction_data.hex()))

                            pass

                        elif instruction_data[0] == 0x02: # CreateAccount
                            # logger.debug("{:>10} {:>6} CreateAccount 0x{}".format(slot, counter, instruction_data[-21:-1].hex()))

                            pass

                        elif instruction_data[0] == 0x03: # Call
                            # logger.debug("{:>10} {:>6} Call 0x{}".format(slot, counter, instruction_data.hex()))

                            pass

                        elif instruction_data[0] == 0x04: # CreateAccountWithSeed
                            # logger.debug("{:>10} {:>6} CreateAccountWithSeed 0x{}".format(slot, counter, instruction_data.hex()))

                            pass

                        elif instruction_data[0] == 0x05: # CallFromRawTrx
                            # logger.debug("{:>10} {:>6} CallFromRawTrx 0x{}".format(slot, counter, instruction_data.hex()))

                            # collateral_pool_buf = instruction_data[1:5]
                            # from_addr = instruction_data[5:25]
                            sign = instruction_data[25:90]
                            unsigned_msg = instruction_data[90:]

                            (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, sign)

                            got_result = get_trx_results(trx)
                            if got_result is not None:
                                self.submit_transaction(eth_trx, eth_signature, from_address, got_result, [signature])
                            else:
                                logger.error("RESULT NOT FOUND IN 05\n{}".format(json.dumps(trx, indent=4, sort_keys=True)))

                        elif instruction_data[0] == 0x09: # PartialCallFromRawEthereumTX
                            # logger.debug("{:>10} {:>6} PartialCallFromRawEthereumTX 0x{}".format(slot, counter, instruction_data.hex()))

                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]

                            if storage_account in continue_table:
                                # collateral_pool_buf = instruction_data[1:5]
                                # step_count = instruction_data[5:13]
                                # from_addr = instruction_data[13:33]

                                sign = instruction_data[33:98]
                                unsigned_msg = instruction_data[98:]

                                (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, sign)

                                continue_result = continue_table[storage_account]

                                self.submit_transaction(eth_trx, eth_signature, from_address, continue_result.results, continue_result.signatures)

                                del continue_table[storage_account]
                            else:
                                self.add_hunged_storage(trx, storage_account)

                        elif instruction_data[0] == 0x0a: # Continue
                            # logger.debug("{:>10} {:>6} Continue 0x{}".format(slot, counter, instruction_data.hex()))

                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]

                            if storage_account in continue_table:
                                continue_table[storage_account].signatures.append(signature)
                            else:
                                got_result = get_trx_results(trx)
                                if got_result is not None:
                                    continue_table[storage_account] =  ContinueStruct(signature, got_result)
                                else:
                                    self.add_hunged_storage(trx, storage_account)


                        elif instruction_data[0] == 0x0b: # ExecuteTrxFromAccountDataIterative
                            # logger.debug("{:>10} {:>6} ExecuteTrxFromAccountDataIterative 0x{}".format(slot, counter, instruction_data.hex()))

                            holder_account =  trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][1]]

                            if storage_account in continue_table:
                                continue_table[storage_account].signatures.append(signature)

                                if holder_account in holder_table:
                                    # logger.debug("holder_account found")
                                    # logger.debug("Strange behavior. Pay attention.")
                                    holder_table[holder_account] = HolderStruct(storage_account)
                                else:
                                    holder_table[holder_account] = HolderStruct(storage_account)
                            else:
                                self.add_hunged_storage(trx, storage_account)


                        elif instruction_data[0] == 0x0c: # Cancel
                            # logger.debug("{:>10} {:>6} Cancel 0x{}".format(slot, counter, instruction_data.hex()))

                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
                            continue_table[storage_account] = ContinueStruct(signature, (None, "0x0", None, None, trx['slot']))

                        elif instruction_data[0] == 0x0c:
                            # logger.debug("{:>10} {:>6} PartialCallOrContinueFromRawEthereumTX 0x{}".format(slot, counter, instruction_data.hex()))

                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]

                            # collateral_pool_buf = instruction_data[1:5]
                            # step_count = instruction_data[5:13]
                            # from_addr = instruction_data[13:33]

                            sign = instruction_data[33:98]
                            unsigned_msg = instruction_data[98:]

                            (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, sign)

                            if storage_account in continue_table:
                                continue_result = continue_table[storage_account]

                                self.submit_transaction(eth_trx, eth_signature, from_address, continue_result.results, continue_result.signatures)

                                del continue_table[storage_account]
                            else:
                                got_result = get_trx_results(trx)
                                if got_result is not None:
                                    self.submit_transaction(eth_trx, eth_signature, from_address, got_result, [signature])
                                else:
                                    self.add_hunged_storage(trx, storage_account)

                        elif instruction_data[0] == 0x0d:
                            # logger.debug("{:>10} {:>6} ExecuteTrxFromAccountDataIterativeOrContinue 0x{}".format(slot, counter, instruction_data.hex()))

                            holder_account =  trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][1]]

                            if storage_account in continue_table:
                                continue_table[storage_account].signatures.append(signature)

                                if holder_account in holder_table:
                                    # logger.debug("holder_account found")
                                    # logger.debug("Strange behavior. Pay attention.")
                                    holder_table[holder_account] = HolderStruct(storage_account)
                                else:
                                    holder_table[holder_account] = HolderStruct(storage_account)
                            else:
                                got_result = get_trx_results(trx)
                                if got_result is not None:
                                    continue_table[storage_account] =  ContinueStruct(signature, got_result)
                                    holder_table[holder_account] = HolderStruct(storage_account)
                                else:
                                    self.add_hunged_storage(trx, storage_account)

                        if instruction_data[0] > 0x0e:
                            logger.debug("{:>10} {:>6} Unknown 0x{}".format(slot, counter, instruction_data.hex()))

                            pass


    def submit_transaction(self, eth_trx, eth_signature, from_address, got_result, signatures):
        (logs, status, gas_used, return_value, slot) = got_result
        (_slot, block_hash) = self.get_block(slot)
        if logs:
            for rec in logs:
                rec['transactionHash'] = eth_signature
                rec['blockHash'] = block_hash
            self.logs_db.push_logs(logs)
        self.ethereum_trx[eth_signature] = {
            'eth_trx': eth_trx,
            'slot': slot,
            'logs': logs,
            'status': status,
            'gas_used': gas_used,
            'return_value': return_value,
            'from_address': from_address,
        }
        self.eth_sol_trx[eth_signature] = signatures
        for idx, sig in enumerate(signatures):
            self.sol_eth_trx[sig] = {
                'idx': idx,
                'eth': eth_signature,
            }
        self.blocks_by_hash[block_hash] = slot

        logger.debug(eth_signature + " " + status)


    def gather_blocks(self):
        max_slot = self.client.get_slot(commitment="recent")["result"]

        last_block = self.constants['last_block']
        if last_block + UPDATE_BLOCK_COUNT < max_slot:
            max_slot = last_block + UPDATE_BLOCK_COUNT
        slots = self.client._provider.make_request("getBlocks", last_block, max_slot, {"commitment": "confirmed"})["result"]

        pool = ThreadPool(PARALLEL_REQUESTS)
        results = pool.map(self.get_block, slots)

        for block_result in results:
            (slot, block_hash) = block_result
            self.blocks_by_hash[block_hash] = slot

        self.constants['last_block'] = max_slot


    def get_block(self, slot):
        retry = True

        while retry:
            try:
                block = self.client._provider.make_request("getBlock", slot, {"commitment":"confirmed", "transactionDetails":"none", "rewards":False})['result']
                block_hash = '0x' + base58.b58decode(block['blockhash']).hex()
                retry = False
            except Exception as err:
                logger.debug(err)
                time.sleep(1)

        return (slot, block_hash)


    def add_hunged_storage(self, trx, storage):
        if abs(trx['slot'] - self.current_slot) > 30:
            self.blocked_storages.add(storage)


def run_indexer():
    logging.basicConfig(format='%(asctime)s - pid:%(process)d [%(levelname)-.1s] %(funcName)s:%(lineno)d - %(message)s')
    logger.setLevel(logging.DEBUG)
    indexer = Indexer()
    indexer.run(False)


if __name__ == "__main__":
    run_indexer()
