from web3 import Web3
from web3.module import Module
from web3.method import Method, default_root_munger
from web3.providers.base import BaseProvider
from typing import Optional, Tuple, Callable, Union
from web3.types import RPCEndpoint, TypedDict, HexBytes, HexStr, ChecksumAddress


NeonAccountData = TypedDict(
    "NeonAccountData",
    {
        "address": HexBytes,
        "transactionCount": int,
        "balance": int,
        "chain_id": int,
        "solanaAddress": str,
    },
    total=False,
)


class Neon(Module):
    _neon_emulate = RPCEndpoint('neon_emulate')

    def _neon_emulate_munger(self, tx: bytearray) -> Tuple[str]:
        return (bytes(tx).hex(),)

    neon_emulate = Method(
        _neon_emulate,
        mungers=[_neon_emulate_munger],
    )

    _neon_getEvmParams = RPCEndpoint('neon_getEvmParams')

    neon_getEvmParams = Method(
        _neon_getEvmParams,
        mungers=[],
    )

    _neon_gasPrice = RPCEndpoint('neon_gasPrice')

    neon_gasPrice = Method(
        _neon_gasPrice,
        mungers=[default_root_munger]
    )

    _neon_getAccount: Method[Callable[[Union[HexStr, bytes]], NeonAccountData]] = Method(
        RPCEndpoint('neon_getAccount'),
        mungers=[default_root_munger],
    )

    def neon_getAccount(self, account: Union[HexStr, bytes]) -> NeonAccountData:
        return self._neon_getAccount(account)


class NeonWeb3(Web3):
    neon: Neon

    def __init__(self, provider:  Optional[BaseProvider] = None):
        super().__init__(provider)
        setattr(self, "neon", Neon(self))
