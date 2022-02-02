from typing import Dict, Optional, Any
from .eth_proto import Trx as EthTx


def get_from_dict(src: Dict, *path) -> Optional[Any]:
    """Provides smart getting values from python dictionary"""
    val = src
    for key in path:
        if not isinstance(val, dict):
            return None
        val = val.get(key)
        if val is None:
            return None
    return val


def get_holder_msg(eth_trx: EthTx):
    unsigned_msg = eth_trx.unsigned_msg()
    return  eth_trx.signature() + len(unsigned_msg).to_bytes(8, byteorder="little") + unsigned_msg
