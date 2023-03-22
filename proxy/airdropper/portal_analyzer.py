from .airdropper import AirdropperState, AirdropperTrxAnalyzer, AirdropperTxInfo
from ..common_neon.eth_proto import NeonTx
from ..common_neon.address import NeonAddress
from typing import Set

import logging
from construct import ConstructError, Const, Struct, GreedyBytes, Byte, Bytes, BytesInteger, this, Int32ub, Int16ub, Int64ub, Switch, Enum

LOG = logging.getLogger(__name__)

Signer = Struct(
    "guardianIndex" / Byte,
    "r" / Bytes(32),
    "s" / Bytes(32),
    "v" / Byte,
)

COMPLETE_TRANSFER = bytes.fromhex('c6878519')

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
    "payload" / Switch(this.payloadID,
        {
            "Transfer" : Struct(
                "amount" / BytesInteger(32),
                "tokenAddress" / Bytes(32),
                "tokenChain" / Int16ub,
                "to" / Bytes(32),
                "toChain" / Int16ub,
                "fee" / BytesInteger(32),
            ),
            "TransferWithPayload" : Struct (
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

class PortalTrxAnalyzer(AirdropperTrxAnalyzer):
    # tokens_whitelist - the whitelist of tokens for the transfer of which to airdrop NEONs
    #    this set should contains next items: "tokenChain:tokenAddress",
    #    where `tokenChain` is originally chain of token in term of Portal bridge numbers
    #          `tokenAddress` is address of token in hexadecimal lowercase form with '0x' prefix
    # If tokens_whitelist is empty then any token transfer lead to airdrop
    def __init__(self, tokens_whitelist: Set[str]):
        self.tokens_whitelist = tokens_whitelist
        pass

    def process(self, neon_tx: AirdropperTxInfo, state: AirdropperState):
        callData = bytes.fromhex(neon_tx._neon_receipt.neon_tx.calldata[2:])
        LOG.debug(f'callData: {callData.hex()}')
        if callData[0:4] == COMPLETE_TRANSFER:
            offset = int.from_bytes(callData[4:36],'big')
            length = int.from_bytes(callData[36:68],'big')
            data = callData[36+offset:36+offset+length]
            vaa = VAA.parse(data)

            tokenAddress = NeonAddress(vaa.payload.tokenAddress[12:32])
            tokenID = f"{vaa.payload.tokenChain}:{tokenAddress}"
            if len(self.tokens_whitelist) == 0 or tokenID in self.tokens_whitelist:
                to = NeonAddress(vaa.payload.to[12:])
                LOG.info(f"Portal transfer: {vaa.payload.amount} of {tokenID} token to {to}")
                state.schedule_airdrop(to)