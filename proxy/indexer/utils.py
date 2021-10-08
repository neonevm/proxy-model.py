import base58
import rlp
import logging
from web3.auto.gethdev import w3
from ethereum.utils import sha3
from ethereum.transactions import Transaction
from eth_utils import big_endian_to_int

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def check_error(trx):
    if 'meta' in trx and 'err' in trx['meta'] and trx['meta']['err'] is not None:
        # logger.debug("Got err trx")
        # logger.debug("\n{}".format(json.dumps(trx['meta']['err'])))
        return True
    return False

def get_trx_results(trx):
    slot = trx['slot']
    block_number = hex(slot)
    block_hash = '0x%064x'%slot
    got_result = False
    logs = []
    status = "0x1"
    gas_used = 0
    return_value = bytes
    log_index = 0
    for inner in (trx['meta']['innerInstructions']):
        for event in inner['instructions']:
            log = base58.b58decode(event['data'])
            instruction = log[:1]
            if (int().from_bytes(instruction, "little") == 7):  # OnEvent evmInstruction code
                address = log[1:21]
                count_topics = int().from_bytes(log[21:29], 'little')
                topics = []
                pos = 29
                for _ in range(count_topics):
                    topic_bin = log[pos:pos + 32]
                    topics.append('0x'+topic_bin.hex())
                    pos += 32
                data = log[pos:]
                rec = { 'address': '0x'+address.hex(),
                        'topics': topics,
                        'data': '0x'+data.hex(),
                        'transactionLogIndex': hex(0),
                        'transactionIndex': hex(inner['index']),
                        'blockNumber': block_number,
                        # 'transactionHash': trxId, # set when transaction found
                        'logIndex': hex(log_index),
                        'blockHash': block_hash
                    }
                logs.append(rec)
                log_index +=1
            elif int().from_bytes(instruction, "little") == 6:  # OnReturn evmInstruction code
                got_result = True
                if log[1] < 0xd0:
                    status = "0x1"
                else:
                    status = "0x0"
                gas_used = int.from_bytes(log[2:10], 'little')
                return_value = log[10:].hex()

    if got_result:
        return (logs, status, gas_used, return_value, slot)
    else:
        return None


def get_trx_receipts(unsigned_msg, signature):
    eth_trx = rlp.decode(unsigned_msg, Transaction)

    v = int(signature[64]) + 35 + 2 * eth_trx[6]
    r = big_endian_to_int(signature[0:32])
    s = big_endian_to_int(signature[32:64])

    eth_trx_raw = rlp.encode(Transaction(eth_trx[0], eth_trx[1], eth_trx[2], eth_trx[3], eth_trx[4], eth_trx[5], v, r, s), Transaction)
    eth_signature = '0x' + sha3(eth_trx_raw).hex()
    from_address = w3.eth.account.recover_transaction(eth_trx_raw.hex()).lower()

    return (eth_trx_raw.hex(), eth_signature, from_address)
