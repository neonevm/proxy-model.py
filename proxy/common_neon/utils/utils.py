from __future__ import annotations
from typing import Dict, Any, List

import json
import base58

from enum import Enum
from eth_utils import big_endian_to_int

#TODO: move it out from here
from ..environment_data import EVM_LOADER_ID, LOG_FULL_OBJECT_INFO

from ..eth_proto import Trx as EthTx


def str_fmt_object(obj: Any) -> str:
    type_name = 'Type'
    class_prefix = "<class '"

    def lookup(d: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in d.items():
            key = key.lstrip('_')
            if isinstance(value, Enum):
                value = str(value)
                idx = value.find('.')
                if idx != -1:
                    value = value[idx + 1:]
                result[key] = value
            elif LOG_FULL_OBJECT_INFO:
                result[key] = value
            elif value is None:
                pass
            elif isinstance(value, bool):
                if value:
                    result[key] = value
            elif isinstance(value, list) or isinstance(value, set):
                if len(value) > 0:
                    result[f'len({key})'] = len(value)
            elif isinstance(value, str) or isinstance(value, bytes) or isinstance(value, bytearray):
                if len(value) == 0:
                    continue
                if isinstance(value, bytes) or isinstance(value, bytearray):
                    value = '0x' + value.hex()
                if len(value) > 130:
                    value = value[:130] + '...'
                result[key] = value
            elif hasattr(value, '__str__'):
                value_str = str(value)
                if value_str.startswith(f'<{type_name} ') and hasattr(value, '__dict__'):
                    result[key] = lookup(value.__dict__)
                else:
                    result[key] = value_str
            else:
                result[key] = value
        return result

    name = f'{type(obj)}'
    name = name[name.rfind('.') + 1:-2]
    if name.startswith(class_prefix):
        name = name[len(class_prefix):]

    if hasattr(obj, '__dict__'):
        members = json.dumps(lookup(obj.__dict__), skipkeys=True, sort_keys=True)
    elif isinstance(obj, dict):
        members = json.dumps(lookup(obj), skipkeys=True, sort_keys=True)
    else:
        members = None

    return f'<{type_name} {name}>: {members}'


# TODO: move to separate file
class SolanaBlockInfo:
    def __init__(self, slot: int, hash=None, time=None, parent_block_slot=None, is_finalized=False, is_fake=False):
        # TODO: rename to block_slot
        self.slot = slot
        self.is_finalized = is_finalized
        self.is_fake = is_fake
        # TODO: rename to block_hash
        self.hash = hash
        # TODO: rename to block_time
        self.time = time
        self.parent_block_slot = parent_block_slot
        # TODO: rename to block_parent_hash
        self.parent_hash = None
        # TODO: remove
        self.signs = []

    def __str__(self) -> str:
        return str_fmt_object(self)

    def __getstate__(self) -> Dict:
        return self.__dict__

    def __setstate__(self, src):
        self.__dict__ = src

    def is_empty_fake(self) -> bool:
        return self.is_fake and (len(self.signs) == 0)

    def is_empty(self) -> bool:
        return self.time is None


# TODO: move to separate file
class NeonTxResultInfo:
    def __init__(self):
        self._set_defaults()

    def __str__(self):
        return str_fmt_object(self)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, src):
        self.__dict__ = src

    def _set_defaults(self):
        self.logs = []
        self.status = "0x0"
        self.gas_used = '0x0'
        self.return_value = bytes()
        self.sol_sign = None
        # TODO: rename to block_slot
        self.slot = -1
        self.block_hash = ''
        self.sol_ix_idx = -1
        self.sol_ix_inner_idx = None

    def _decode_event(self, neon_sign, log, tx_idx):
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
            'transactionHash': neon_sign,
            'transactionIndex': hex(tx_idx), # set when transaction found
            'transactionLogIndex': hex(log_idx),
            'logIndex': hex(log_idx), # set when transaction found
            # 'blockNumber': block_number, # set when transaction found
            # 'blockHash': block_hash # set when transaction found
        }
        self.logs.append(rec)

    def append_record(self, rec):
        self.logs.append(rec)

    def _decode_return(self, log: bytes, ix_idx: int, tx: {}):
        self.status = '0x1' if log[1] < 0xd0 else '0x0'
        self.gas_used = hex(int.from_bytes(log[2:10], 'little'))
        self.return_value = log[10:].hex()
        self.sol_sign = tx['transaction']['signatures'][0]
        self.sol_ix_idx = ix_idx
        self.slot = tx['slot']

    def set_result(self, sol_neon_ix, status, gas_used, return_value):
        # TODO: add types of input parameters
        self.status = status
        self.gas_used = gas_used
        self.return_value = return_value
        self.sol_sign = sol_neon_ix.sol_sign
        self.slot = sol_neon_ix.block_slot
        self.sol_ix_idx = sol_neon_ix.idx
        self.sol_ix_inner_idx = sol_neon_ix.inner_idx

    def fill_block_info(self, block: SolanaBlockInfo):
        self.slot = block.slot
        self.block_hash = block.hash
        for rec in self.logs:
            rec['blockHash'] = block.hash
            rec['blockNumber'] = hex(block.slot)

    def decode(self, neon_sign: str, tx: {}) -> NeonTxResultInfo:
        self._set_defaults()
        meta_ixs = tx['meta']['innerInstructions']
        msg = tx['transaction']['message']
        accounts = msg['accountKeys']

        for inner_ix in meta_ixs:
            ix_idx = inner_ix['index']
            for event in inner_ix['instructions']:
                if accounts[event['programIdIndex']] == EVM_LOADER_ID:
                    log = base58.b58decode(event['data'])
                    evm_ix = int(log[0])
                    if evm_ix == 7:
                        self._decode_event(neon_sign, log, ix_idx)
                    elif evm_ix == 6:
                        self._decode_return(log, ix_idx, tx)
        return self

    def canceled(self, sol_sign: str, slot: int):
        self._set_defaults()
        self.sol_sign = sol_sign
        self.slot = slot

    def is_valid(self) -> bool:
        return self.slot != -1


# TODO: move to separate file
class NeonTxInfo:
    def __init__(self, rlp_sign=None, rlp_data=None):
        self.tx_idx = 0

        self._set_defaults()
        if isinstance(rlp_sign, bytes) and isinstance(rlp_data, bytes):
            self.decode(rlp_sign, rlp_data)

    def __str__(self):
        return str_fmt_object(self)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, src):
        self.__dict__ = src

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

            if utx.v == 0:
                uv = int(rlp_sign[64]) + 27
            else:
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


# TODO: move to separate file
class NeonTxReceiptInfo:
    def __init__(self, neon_tx: NeonTxInfo, neon_res: NeonTxResultInfo):
        self.neon_tx = neon_tx
        self.neon_res = neon_res

    def __str__(self):
        return str_fmt_object(self)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, src):
        self.__dict__ = src


def get_from_dict(src: Dict, *path) -> Any:
    """Provides smart getting values from python dictionary"""
    val = src
    for key in path:
        if not isinstance(val, dict):
            return None
        val = val.get(key)
        if val is None:
            return None
    return val


def get_holder_msg(eth_trx: EthTx) -> bytes:
    unsigned_msg = eth_trx.unsigned_msg()
    return eth_trx.signature() + len(unsigned_msg).to_bytes(8, byteorder="little") + unsigned_msg
