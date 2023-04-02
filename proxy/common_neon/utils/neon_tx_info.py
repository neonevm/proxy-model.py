from __future__ import annotations
from typing import Optional
from eth_utils import big_endian_to_int

from dataclasses import dataclass

from .utils import str_fmt_object

from ..eth_proto import NeonTx


@dataclass(frozen=True)
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

    _str: str = ''

    def __str__(self) -> str:
        if self._str == '':
            object.__setattr__(self, '_str', str_fmt_object(self))
        return self._str

    @staticmethod
    def from_neon_tx(tx: NeonTx) -> NeonTxInfo:
        return NeonTxInfo(
            v=hex(tx.v),
            r=hex(tx.r),
            s=hex(tx.s),
            sig=tx.hex_tx_sig,
            addr=tx.hex_sender,
            nonce=hex(tx.nonce),
            gas_price=hex(tx.gasPrice),
            gas_limit=hex(tx.gasLimit),
            value=hex(tx.value),
            calldata=tx.hex_call_data,
            to_addr=tx.hex_to_address,
            contract=tx.hex_contract
        )

    @staticmethod
    def from_unsig_data(rlp_sig: bytes, rlp_unsig_data: bytes) -> NeonTxInfo:
        try:
            utx = NeonTx.from_string(rlp_unsig_data)

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
            tx = NeonTx.from_string(rlp_sig_data)
            return NeonTxInfo.from_neon_tx(tx)
        except Exception as e:
            return NeonTxInfo(error=e)

    @staticmethod
    def from_neon_sig(neon_sig: str) -> NeonTxInfo:
        return NeonTxInfo(sig=neon_sig)

    def is_valid(self):
        return (self.addr is not None) and (self.error is None)
