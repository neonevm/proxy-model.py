import logging

from typing import Optional

from construct import (
    Const, Struct, GreedyBytes, Byte, Bytes, BytesInteger,
    Int32ub, Int16ub, Int64ub, Switch, this, Enum, ConstructError
)

from .gas_tank_types import GasTankNeonTxAnalyzer, GasTankTxInfo

from ..common_neon.address import NeonAddress


LOG = logging.getLogger(__name__)

Signer = Struct(
    "guardianIndex" / Byte,
    "r" / Bytes(32),
    "s" / Bytes(32),
    "v" / Byte,
)

METHOD_ID = bytes.fromhex('c6878519')

VAASize = Struct(
    "offset" / BytesInteger(32),
    "length" / BytesInteger(32)
)

VAA = Struct(
    "version" / Const(b"\1"),
    "guardiansetIndex" / Int32ub,
    "signersLen" / Byte,
    "signers" / Signer[this.signersLen],
    "timestamp" / Int32ub,
    "nonce" / Int32ub,
    "emitterChainId" / Int16ub,
    "emitterAddress" / Bytes(32),
    "sequence" / Int64ub,
    "consistencyLevel" / Byte,
    "payloadID" / Enum(Byte, Transfer=1, TransferWithPayload=3),
    "payload" / Switch(this.payloadID, {
            "Transfer": Struct(
                "amount" / BytesInteger(32),
                "tokenAddress" / Bytes(32),
                "tokenChain" / Int16ub,
                "to" / Bytes(32),
                "toChain" / Int16ub,
                "fee" / BytesInteger(32),
            ),
            "TransferWithPayload": Struct(
                "amount" / BytesInteger(32),
                "tokenAddress" / Bytes(32),
                "tokenChain" / Int16ub,
                "to" / Bytes(32),
                "toChain" / Int16ub,
                "fromaddress" / Bytes(32),
                "payload" / GreedyBytes,
            ),
        },
        default=GreedyBytes,
    )
)


class PortalAnalyzer(GasTankNeonTxAnalyzer):
    name = 'Portal'

    def process(self, neon_tx: GasTankTxInfo) -> Optional[NeonAddress]:
        if not self._has_token_whitelist:
            return None

        call_data = bytes.fromhex(neon_tx.neon_tx.calldata[2:])
        if len(call_data) < 69:
            LOG.debug(f'small callData {len(call_data)}')
            return None

        if call_data[:4] != METHOD_ID:
            LOG.debug(f'bad method name {call_data.hex()[:8]}')
            return None

        try:
            vaa_size = VAASize.parse(call_data[4:68])
        except ConstructError as exc:
            LOG.debug(f'Exception on parsing VAASize: {str(exc)}')
            return None

        vaa_offset = 36 + vaa_size.offset
        vaa_len = vaa_offset + vaa_size.length
        if vaa_len > len(call_data):
            LOG.debug(f'size of callData {len(call_data)} is less than size of VAA: {vaa_len}')
            return None

        data = call_data[vaa_offset:vaa_len]
        try:
            vaa = VAA.parse(data)
        except ConstructError as exc:
            LOG.debug(f'Exception on parsing VAA: {str(exc)}')
            return None

        token_address = NeonAddress(vaa.payload.tokenAddress[12:32])
        token_id = f'{vaa.payload.tokenChain}:{token_address}'
        if not self._is_allowed_token(token_id, vaa.payload.amount):
            LOG.debug(f'not allowed token: {str(token_address)}')
            return None

        to = NeonAddress(vaa.payload.to[12:])
        LOG.info(f'Portal transfer: {vaa.payload.amount} of {token_id} token to {to}')
        return to
