import base58
import base64
import json
import logging
import os
import psycopg2
import rlp
import subprocess

from eth_utils import big_endian_to_int
from ethereum.transactions import Transaction as EthTrx
from ethereum.utils import sha3
from solana.account import Account
from solana.publickey import PublicKey
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts
from solana.system_program import SYS_PROGRAM_ID
from solana.sysvar import SYSVAR_CLOCK_PUBKEY, SYSVAR_RENT_PUBKEY
from solana.transaction import AccountMeta, Transaction, TransactionInstruction
from spl.token.constants import TOKEN_PROGRAM_ID
from spl.token.instructions import get_associated_token_address
from web3.auto.gethdev import w3
from logged_groups import logged_group

from ..common_neon.constants import SYSVAR_INSTRUCTION_PUBKEY, INCINERATOR_PUBKEY, KECCAK_PROGRAM
from ..common_neon.layouts import STORAGE_ACCOUNT_INFO_LAYOUT
from ..environment import SOLANA_URL, EVM_LOADER_ID, ETH_TOKEN_MINT_ID


def check_error(trx):
    if 'meta' in trx and 'err' in trx['meta'] and trx['meta']['err'] is not None:
        # logger.debug("Got err trx")
        # logger.debug("\n{}".format(json.dumps(trx['meta']['err'])))
        return True
    return False


def get_trx_results(trx):
    # init variables for instruction owner checks
    accounts = trx["transaction"]["message"]["accountKeys"]
    evm_loader_instructions = []
    for idx, instruction in enumerate(trx["transaction"]["message"]["instructions"]):
        if accounts[instruction["programIdIndex"]] == EVM_LOADER_ID:
            evm_loader_instructions.append(idx)

    slot = trx['slot']
    block_number = hex(slot)
    got_result = False
    logs = []
    status = "0x1"
    gas_used = 0
    return_value = bytes
    log_index = 0
    for inner in (trx['meta']['innerInstructions']):
        if inner["index"] in evm_loader_instructions:
            for event in inner['instructions']:
                if accounts[event['programIdIndex']] == EVM_LOADER_ID:
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
                        rec = {
                            'address': '0x'+address.hex(),
                            'topics': topics,
                            'data': '0x'+data.hex(),
                            'transactionLogIndex': hex(0),
                            'transactionIndex': hex(inner['index']),
                            'blockNumber': block_number,
                            # 'transactionHash': trxId, # set when transaction found
                            'logIndex': hex(log_index),
                            # 'blockHash': block_hash # set when transaction found
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
    unsigned_msg = bytes(unsigned_msg)
    trx = rlp.decode(unsigned_msg, EthTrx)

    v = int(signature[64]) + 35 + 2 * trx[6]
    r = big_endian_to_int(signature[0:32])
    s = big_endian_to_int(signature[32:64])

    trx_raw = rlp.encode(EthTrx(trx[0], trx[1], trx[2], trx[3], trx[4], trx[5], v, r, s), EthTrx)
    eth_signature = '0x' + sha3(trx_raw).hex()
    from_address = w3.eth.account.recover_transaction(trx_raw).lower()

    return (trx_raw.hex(), eth_signature, from_address)


@logged_group("Indexer")
def get_account_list(client, storage_account, *, logger):
    opts = {
        "encoding": "base64",
        "commitment": "confirmed",
        "dataSlice": {
            "offset": 0,
            "length": 2048,
        }
    }
    result = client._provider.make_request("getAccountInfo", str(storage_account), opts)
    # logger.debug("\n{}".format(json.dumps(result, indent=4, sort_keys=True)))

    info = result['result']['value']
    if info is None:
        raise Exception("Can't get information about {}".format(storage_account))

    data = base64.b64decode(info['data'][0])

    tag = data[0]
    if tag == 0:
        logger.debug("Empty")
        return None
    elif tag == 3:
        logger.debug("Not empty storage")

        acc_list = []
        storage = STORAGE_ACCOUNT_INFO_LAYOUT.parse(data[1:])
        offset = 1 + STORAGE_ACCOUNT_INFO_LAYOUT.sizeof()
        for _ in range(storage.accounts_len):
            some_pubkey = PublicKey(data[offset:offset + 32])
            acc_list.append(str(some_pubkey))
            offset += 32

        return acc_list
    else:
        logger.debug("Not empty other")
        return None


@logged_group("Indexer")
class LogDB:
    def __init__(self):
        POSTGRES_DB = os.environ.get("POSTGRES_DB", "neon-db")
        POSTGRES_USER = os.environ.get("POSTGRES_USER", "neon-proxy")
        POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "neon-proxy-pass")
        POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "localhost")

        self.conn = psycopg2.connect(
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            host=POSTGRES_HOST
        )

        cur = self.conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS
        logs (
            address TEXT,
            blockHash TEXT,
            blockNumber INT,
            topic TEXT,

            transactionHash TEXT,
            transactionLogIndex INT,

            json TEXT,
            UNIQUE(transactionLogIndex, transactionHash, topic)
        );""")
        self.conn.commit()


    def push_logs(self, logs):
        rows = []
        for log in logs:
            for topic in log['topics']:
                rows.append(
                    (
                        log['address'],
                        log['blockHash'],
                        int(log['blockNumber'], 16),
                        topic,
                        log['transactionHash'],
                        int(log['transactionLogIndex'], 16),
                        json.dumps(log)
                    )
                )
        if len(rows):
            # self.debug(rows)
            cur = self.conn.cursor()
            cur.executemany('INSERT INTO logs VALUES (%s, %s, %s, %s,  %s, %s,  %s) ON CONFLICT DO NOTHING', rows)
            self.conn.commit()
        else:
            self.debug("NO LOGS")


    def get_logs(self, fromBlock = None, toBlock = None, address = None, topics = None, blockHash = None):
        queries = []
        params = []

        if fromBlock is not None:
            queries.append("blockNumber >= %s")
            params.append(fromBlock)

        if toBlock is not None:
            queries.append("blockNumber <= %s")
            params.append(toBlock)

        if blockHash is not None:
            blockHash = blockHash.lower()
            queries.append("blockHash = %s")
            params.append(blockHash)

        if topics is not None:
            topics = [item.lower() for item in topics]
            query_placeholder = ", ".join(["%s" for _ in range(len(topics))])
            topics_query = f"topic IN ({query_placeholder})"

            queries.append(topics_query)
            params += topics

        if address is not None:
            if isinstance(address, str):
                address = address.lower()
                queries.append("address = %s")
                params.append(address)
            elif isinstance(address, list):
                address = [item.lower() for item in address]
                query_placeholder = ", ".join(["%s" for _ in range(len(address))])
                address_query = f"address IN ({query_placeholder})"

                queries.append(address_query)
                params += address

        query_string = "SELECT * FROM logs WHERE "
        for idx, query in enumerate(queries):
            query_string += query
            if idx < len(queries) - 1:
                query_string += " AND "

        self.debug(query_string)
        self.debug(params)

        cur = self.conn.cursor()
        cur.execute(query_string, tuple(params))

        rows = cur.fetchall()

        logs = set()
        for row in rows:
            logs.add(row[-1])
        return_list = []
        for log in logs:
            return_list.append(json.loads(log))
        return return_list

    def __del__(self):
        self.conn.close()


@logged_group("Indexer")
class Canceller:
    def __init__(self):
        # Initialize user account
        res = self.call('config', 'get')
        substr = "Keypair Path: "
        path = ""
        for line in res.splitlines():
            if line.startswith(substr):
                path = line[len(substr):].strip()
        if path == "":
            raise Exception("cannot get keypair path")

        with open(path.strip(), mode='r') as file:
            pk = (file.read())
            numbs = list(map(int, pk.strip("[] \n").split(',')))
            numbs = numbs[0:32]
            values = bytes(numbs)
            self.signer = Account(values)

        self.client = Client(SOLANA_URL)

        self.operator = self.signer.public_key()
        self.operator_token = get_associated_token_address(PublicKey(self.operator), ETH_TOKEN_MINT_ID)

    def call(self, *args):
        try:
            cmd = ["solana",
                   "--url", SOLANA_URL,
                   ] + list(args)
            self.debug(cmd)
            return subprocess.check_output(cmd, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            self.debug("ERR: solana error {}".format(err))
            raise

    def unlock_accounts(self, blocked_storages):
        readonly_accs = [
            PublicKey(EVM_LOADER_ID),
            ETH_TOKEN_MINT_ID,
            PublicKey(TOKEN_PROGRAM_ID),
            PublicKey(SYSVAR_CLOCK_PUBKEY),
            PublicKey(SYSVAR_INSTRUCTION_PUBKEY),
            PublicKey(KECCAK_PROGRAM),
            PublicKey(SYSVAR_RENT_PUBKEY),
            PublicKey(INCINERATOR_PUBKEY),
            PublicKey(SYS_PROGRAM_ID),
        ]
        for storage, trx_accs in blocked_storages.items():
            (eth_trx, blocked_accs) = trx_accs
            acc_list = get_account_list(self.client, storage)
            if eth_trx is None:
                self.error("trx is None")
                continue
            if blocked_accs is None:
                self.error("blocked_accs is None")
                continue
            if acc_list is None:
                self.error("acc_list is None. Storage is empty")
                self.error(storage)
                continue

            eth_trx = rlp.decode(bytes.fromhex(eth_trx), EthTrx)
            if acc_list != blocked_accs:
                self.error("acc_list != blocked_accs")
                continue

            if acc_list is not None:
                keys = [
                        AccountMeta(pubkey=storage, is_signer=False, is_writable=True),
                        AccountMeta(pubkey=self.operator, is_signer=True, is_writable=True),
                        AccountMeta(pubkey=self.operator_token, is_signer=False, is_writable=True),
                        AccountMeta(pubkey=acc_list[4], is_signer=False, is_writable=True),
                        AccountMeta(pubkey=INCINERATOR_PUBKEY, is_signer=False, is_writable=True),
                        AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False)
                    ]
                for acc in acc_list:
                    keys.append(AccountMeta(pubkey=acc, is_signer=False, is_writable=(False if acc in readonly_accs else True)))

                trx = Transaction()
                trx.add(TransactionInstruction(
                    program_id=EVM_LOADER_ID,
                    data=bytearray.fromhex("15") + eth_trx[0].to_bytes(8, 'little'),
                    keys=keys
                ))

                self.debug("Send Cancel")
                try:
                    self.client.send_transaction(trx, self.signer, opts=TxOpts(preflight_commitment=Confirmed))
                except Exception as err:
                    self.error(err)
                else:
                    self.debug("Canceled")
                    self.debug(acc_list)
