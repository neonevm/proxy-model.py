from __future__ import annotations

import base58
import base64
import json
import psycopg2
import subprocess
import os

from eth_utils import big_endian_to_int
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
from logged_groups import logged_group

from ..common_neon.address import ether2program
from ..common_neon.constants import SYSVAR_INSTRUCTION_PUBKEY, INCINERATOR_PUBKEY, KECCAK_PROGRAM
from ..common_neon.layouts import STORAGE_ACCOUNT_INFO_LAYOUT, CODE_ACCOUNT_INFO_LAYOUT, ACCOUNT_INFO_LAYOUT
from ..common_neon.eth_proto import Trx as EthTx
from ..common_neon.utils import get_from_dict
from ..environment import SOLANA_URL, EVM_LOADER_ID, ETH_TOKEN_MINT_ID


from proxy.indexer.pg_common import POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_HOST
from proxy.indexer.pg_common import encode, decode


FINALIZED = os.environ.get('FINALIZED', 'finalized')


def check_error(trx):
    if 'meta' in trx and 'err' in trx['meta'] and trx['meta']['err'] is not None:
        return True
    return False


def str_fmt_object(obj):
    name = f'{type(obj)}'
    name = name[name.rfind('.') + 1:-2]
    lookup = lambda o: o.__dict__ if hasattr(o, '__dict__') else None
    members = {json.dumps(obj, skipkeys=True, default=lookup, sort_keys=True)}
    return f'{name}: {members}'


class SolanaIxSignInfo:
    def __init__(self, sign: str, slot: int, idx: int):
        self.sign = sign  # Solana transaction signature
        self.slot = slot  # Solana block slot
        self.idx  = idx   # Instruction index

    def __str__(self):
        return f'{self.slot} {self.sign} {self.idx}'

    def __hash__(self):
        return hash((self.sign, self.slot, self.idx))

    def __eq__(self, other):
        return (self.sign, self.slot, self.idx) == (other.sign, other.slot, other.idx)


class NeonTxResultInfo:
    def __init__(self, tx=None, ix_idx=-1):
        if not isinstance(tx, dict):
            self._set_defaults()
        else:
            self.decode(tx, ix_idx)

    def __str__(self):
        return str_fmt_object(self)

    def _set_defaults(self):
        self.logs = []
        self.status = "0x0"
        self.gas_used = '0x0'
        self.return_value = bytes()
        self.sol_sign = None
        self.slot = -1
        self.idx = -1

    def _decode_event(self, log, tx_idx):
        log_idx = len(self.logs)
        address = log[1:21]
        count_topics = int().from_bytes(log[21:29], 'little')
        topics = []
        pos = 29
        for _ in range(count_topics):
            topic_bin = log[pos:pos + 32]
            topics.append('0x' + topic_bin.hex())
            pos += 32
        data = log[pos:]
        rec = {
            'address': '0x' + address.hex(),
            'topics': topics,
            'data': '0x' + data.hex(),
            'transactionLogIndex': hex(0),
            'transactionIndex': hex(tx_idx),
            # 'blockNumber': block_number, # set when transaction found
            # 'transactionHash': trxId, # set when transaction found
            'logIndex': hex(log_idx),
            # 'blockHash': block_hash # set when transaction found
        }
        self.logs.append(rec)

    def _decode_return(self, log: bytes, ix_idx: int, tx: {}):
        self.status = '0x1' if log[1] < 0xd0 else '0x0'
        self.gas_used = hex(int.from_bytes(log[2:10], 'little'))
        self.return_value = log[10:].hex()
        self.sol_sign = tx['transaction']['signatures'][0]
        self.slot = tx['slot']
        self.idx = ix_idx

    def decode(self, tx: {}, ix_idx=-1) -> NeonTxResultInfo:
        self._set_defaults()
        meta_ixs = tx['meta']['innerInstructions']
        msg = tx['transaction']['message']
        msg_ixs = msg["instructions"]
        accounts = msg['accountKeys']

        evm_ix_idxs = []
        if ix_idx == -1:
            for idx, ix in enumerate(msg_ixs):
                if accounts[ix["programIdIndex"]] == EVM_LOADER_ID:
                    evm_ix_idxs.append(idx)
        else:
            evm_ix_idxs.append(ix_idx)

        for inner_ix in meta_ixs:
            ix_idx = inner_ix['index']
            if ix_idx in evm_ix_idxs:
                for event in inner_ix['instructions']:
                    if accounts[event['programIdIndex']] == EVM_LOADER_ID:
                        log = base58.b58decode(event['data'])
                        evm_ix = int(log[0])
                        if evm_ix == 7:
                            self._decode_event(log, ix_idx)
                        elif evm_ix == 6:
                            self._decode_return(log, ix_idx, tx)
        return self

    def clear(self):
        self._set_defaults()

    def is_valid(self) -> bool:
        return self.slot != -1


@logged_group("neon.Indexer")
class NeonTxInfo:
    def __init__(self, rlp_sign=None, rlp_data=None):
        self._set_defaults()
        if isinstance(rlp_sign, bytes) and isinstance(rlp_data, bytes):
            self.decode(rlp_sign, rlp_data)

    def __str__(self):
        return str_fmt_object(self)

    def _set_defaults(self):
        self.addr = None
        self.sign = None
        self.nonce = None
        self.gas_price = None
        self.gas_limit = None
        self.to_addr = None
        self.contract = None
        self.value = None
        self.calldata = None
        self.v = None
        self.r = None
        self.s = None
        self.error = None

    def init_from_eth_tx(self, tx: EthTx):
        self.v = hex(tx.v)
        self.r = hex(tx.r)
        self.s = hex(tx.s)

        self.sign = '0x' + tx.hash_signed().hex()
        self.addr = '0x' + tx.sender()

        self.nonce = hex(tx.nonce)
        self.gas_price = hex(tx.gasPrice)
        self.gas_limit = hex(tx.gasLimit)
        self.value = hex(tx.value)
        self.calldata = '0x' + tx.callData.hex()

        if not tx.toAddress:
            self.to_addr = None
            self.contract = '0x' + tx.contract()
        else:
            self.to_addr = '0x' + tx.toAddress.hex()
            self.contract = None

    def decode(self, rlp_sign: bytes, rlp_data: bytes) -> NeonTxInfo:
        self._set_defaults()

        try:
            utx = EthTx.fromString(rlp_data)

            uv = int(rlp_sign[64]) + 35 + 2 * utx.v
            ur = big_endian_to_int(rlp_sign[0:32])
            us = big_endian_to_int(rlp_sign[32:64])

            tx = EthTx(utx.nonce, utx.gasPrice, utx.gasLimit, utx.toAddress, utx.value, utx.callData, uv, ur, us)
            self.init_from_eth_tx(tx)
        except Exception as e:
            self.error = e
        return self

    def clear(self):
        self._set_defaults()

    def is_valid(self):
        return (self.addr is not None) and (not self.error)


@logged_group("neon.Indexer")
def get_accounts_from_storage(client, storage_account, *, logger):
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


@logged_group("neon.Indexer")
def get_accounts_by_neon_address(client: Client, neon_address, *, logger):
    pda_address, _nonce = ether2program(neon_address)
    reciept = client.get_account_info(pda_address, commitment=Confirmed)
    account_info = get_from_dict(reciept, 'result', 'value')
    if account_info is None:
        logger.debug(f"account_info is None")
        logger.debug(f"pda_address({pda_address})")
        logger.debug(f"reciept({reciept})")
        return None, None
    data = base64.b64decode(account_info['data'][0])
    if len(data) < ACCOUNT_INFO_LAYOUT.sizeof():
        logger.debug(f"{len(data)} < {ACCOUNT_INFO_LAYOUT.sizeof()}")
        return None, None
    account = ACCOUNT_INFO_LAYOUT.parse(data)
    code_account = None
    if account.code_account != [0]*32:
        code_account = str(PublicKey(account.code_account))
    return pda_address, code_account


@logged_group("neon.Indexer")
def get_code_from_account(client: Client, address, *, logger):
    reciept = client.get_account_info(address, commitment=Confirmed)
    code_account_info = get_from_dict(reciept, 'result', 'value')
    if code_account_info is None:
        logger.debug(f"code_account_info is None")
        logger.debug(f"code_address({address})")
        logger.debug(f"reciept({reciept})")
        return None
    data = base64.b64decode(code_account_info['data'][0])
    if len(data) < CODE_ACCOUNT_INFO_LAYOUT.sizeof():
        return None
    storage = CODE_ACCOUNT_INFO_LAYOUT.parse(data)
    offset = CODE_ACCOUNT_INFO_LAYOUT.sizeof()
    if len(data) < offset + storage.code_size:
        return None
    return '0x' + data[offset:][:storage.code_size].hex()


@logged_group("neon.Indexer")
class BaseDB:
    def __init__(self):
        self._conn = psycopg2.connect(
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            host=POSTGRES_HOST
        )
        self._conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = self._conn.cursor()
        cursor.execute(self._create_table_sql())

    def _create_table_sql(self) -> str:
        assert False, 'No script for the table'

    def _fetchone(self, values, keys, order_list=None) -> str:
        cursor = self._conn.cursor()

        where_cond = '1=1'
        where_keys = []
        for name, value in keys:
            where_cond += f' AND {name} = %s'
            where_keys.append(value)

        order_cond = ''
        if order_list:
            order_cond = 'ORDER BY ' + ', '.join(order_list)

        cursor.execute(f'SELECT {",".join(values)} FROM {self._table_name} WHERE {where_cond} {order_cond}', where_keys)
        return cursor.fetchone()

    def __del__(self):
        self._conn.close()

    def decode_list(self, v):
        return [] if not v else decode(v)

    def encode_list(self, v: []):
        return None if (not v) or (len(v) == 0) else encode(v)


class LogDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self)

    def _create_table_sql(self) -> str:
        self._table_name = 'neon_transaction_logs'
        return f"""
            CREATE TABLE IF NOT EXISTS {self._table_name} (
                address CHAR(42),
                blockHash CHAR(66),
                blockNumber BIGINT,
                slot BIGINT,
                finalized BOOLEAN,

                transactionHash CHAR(66),
                transactionLogIndex INT,
                topic TEXT,

                json TEXT,

                UNIQUE(transactionLogIndex, transactionHash, topic, slot, finalized)
            );
            CREATE INDEX IF NOT EXISTS {self._table_name}_finalized ON {self._table_name}(slot, finalized);
            """

    def push_logs(self, logs, block):
        rows = []
        for log in logs:
            for topic in log['topics']:
                rows.append(
                    (
                        log['address'],
                        log['blockHash'],
                        int(log['blockNumber'], 16),
                        block.slot,
                        block.finalized,
                        log['transactionHash'],
                        int(log['transactionLogIndex'], 16),
                        topic,
                        json.dumps(log)
                    )
                )
        if len(rows):
            # logger.debug(rows)
            cur = self._conn.cursor()
            cur.executemany(f'''
                            INSERT INTO {self._table_name}(address, blockHash, blockNumber, slot, finalized,
                                            transactionHash, transactionLogIndex, topic, json)
                            VALUES (%s, %s, %s, %s,  %s, %s,  %s, %s, %s) ON CONFLICT DO NOTHING''', rows)
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

        if topics is not None and len(topics) > 0:
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
            elif isinstance(address, list) and len(address) > 0:
                address = [item.lower() for item in address]
                query_placeholder = ", ".join(["%s" for _ in range(len(address))])
                address_query = f"address IN ({query_placeholder})"

                queries.append(address_query)
                params += address

        query_string = f"SELECT * FROM {self._table_name} WHERE "
        for idx, query in enumerate(queries):
            query_string += query
            if idx < len(queries) - 1:
                query_string += " AND "

        self.debug(query_string)
        self.debug(params)

        cur = self._conn.cursor()
        cur.execute(query_string, tuple(params))

        rows = cur.fetchall()

        logs = set()
        for row in rows:
            logs.add(row[-1])
        return_list = []
        for log in logs:
            return_list.append(json.loads(log))
        return return_list

    def del_not_finalized(self, from_slot: int, to_slot: int):
        cursor = self._conn.cursor()
        cursor.execute(f'DELETE FROM {self._table_name} WHERE slot >= %s AND slot <= %s AND finalized = false',
                       (from_slot, to_slot))


@logged_group("neon.Indexer")
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
            self.error("ERR: solana error {}".format(err))
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
        for storage, tx_accounts in blocked_storages.items():
            (neon_tx, blocked_accounts) = tx_accounts
            if blocked_accounts is None:
                self.error(f"Emtpy blocked accounts for the Neon tx {neon_tx}.")

            if blocked_accounts is not None:
                keys = [
                        AccountMeta(pubkey=storage, is_signer=False, is_writable=True),
                        AccountMeta(pubkey=self.operator, is_signer=True, is_writable=True),
                        AccountMeta(pubkey=self.operator_token, is_signer=False, is_writable=True),
                        AccountMeta(pubkey=blocked_accounts[4], is_signer=False, is_writable=True),
                        AccountMeta(pubkey=INCINERATOR_PUBKEY, is_signer=False, is_writable=True),
                        AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False)
                    ]
                for acc in blocked_accounts:
                    keys.append(AccountMeta(pubkey=acc, is_signer=False, is_writable=(False if acc in readonly_accs else True)))

                trx = Transaction()
                nonce = int(neon_tx.nonce, 16)
                trx.add(TransactionInstruction(
                    program_id=EVM_LOADER_ID,
                    data=bytearray.fromhex("15") + nonce.to_bytes(8, 'little'),
                    keys=keys
                ))

                self.debug("Send Cancel")
                try:
                    self.client.send_transaction(trx, self.signer, opts=TxOpts(preflight_commitment=Confirmed))
                except Exception as err:
                    self.error(err)
                else:
                    self.debug(f"Canceled: {blocked_accounts}")
