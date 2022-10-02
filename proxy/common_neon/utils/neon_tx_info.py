from __future__ import annotations
from typing import Optional
from eth_utils import big_endian_to_int

import dataclasses

from .utils import str_fmt_object

from ..eth_proto import NeonTx


@dataclasses.dataclass
class NeonTxInfo:
    addr: Optional[str] = None
    sig: str = ''
    nonce: str = ''
    gas_price: str = ''
    gas_limit: str = ''
    to_addr: Optional[str] = None
    contract: Optional[str] = None
    value: str = ''
    calldata: str = ''
    v: str = ''
    r: str = ''
    s: str = ''
    error: Optional[Exception] = None

    def __str__(self) -> str:
        return str_fmt_object(self)

    @staticmethod
    def from_neon_tx(tx: NeonTx) -> NeonTxInfo:
        if not tx.toAddress:
            to_addr = None
            contract = '0x' + tx.contract()
        else:
            to_addr = '0x' + tx.toAddress.hex()
            contract = None

        return NeonTxInfo(
            v=hex(tx.v),
            r=hex(tx.r),
            s=hex(tx.s),
            sig='0x' + tx.hash_signed().hex().lower(),
            addr='0x' + tx.sender(),
            nonce=hex(tx.nonce),
            gas_price=hex(tx.gasPrice),
            gas_limit=hex(tx.gasLimit),
            value=hex(tx.value),
            calldata='0x' + tx.callData.hex(),
            to_addr=to_addr,
            contract=contract
        )

    @staticmethod
    def from_unsig_data(rlp_sig: bytes, rlp_unsig_data: bytes) -> NeonTxInfo:
        try:
            utx = NeonTx.fromString(rlp_unsig_data)

            if utx.v == 0:
                uv = int(rlp_sig[64]) + 27
            else:
                uv = int(rlp_sig[64]) + 35 + 2 * utx.v
            ur = big_endian_to_int(rlp_sig[0:32])
            us = big_endian_to_int(rlp_sig[32:64])

            tx = NeonTx(utx.nonce, utx.gasPrice, utx.gasLimit, utx.toAddress, utx.value, utx.callData, uv, ur, us)
            return NeonTxInfo.from_neon_tx(tx)
        except Exception as e:
            return NeonTxInfo(error=e)

    @staticmethod
    def from_sig_data(rlp_sig_data: bytes) -> NeonTxInfo:
        try:
            tx = NeonTx.fromString(rlp_sig_data)
            return NeonTxInfo.from_neon_tx(tx)
        except Exception as e:
            return NeonTxInfo(error=e)

    @staticmethod
    def from_neon_sig(neon_sig: str) -> NeonTxInfo:
        return NeonTxInfo(sig=neon_sig)

    def is_valid(self):
        return (self.addr is not None) and (self.error is None)
