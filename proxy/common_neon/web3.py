import dataclasses

from web3 import Web3
from web3.module import Module
from web3.method import Method, default_root_munger
from web3.providers.base import BaseProvider
from typing import Optional, Tuple, Callable, Union
from web3.types import RPCEndpoint, HexBytes, ChecksumAddress, Address, BlockIdentifier


@dataclasses.dataclass
class NeonAccountData:
    address: HexBytes
    transactionCount: int
    balance: int
    chainId: int
    solanaAddress: str


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

    _neon_getAccount = RPCEndpoint('neon_getAccount')

    def _get_account_munger(
        self,
        account: Union[Address, ChecksumAddress, str],
        block_identifier: Optional[BlockIdentifier] = None,
    ) -> Tuple[str, BlockIdentifier]:
        if block_identifier is None:
            block_identifier = 'latest'
        if isinstance(account, bytes):
            account = '0x' + account.hex()
        return account, block_identifier

    _neon_get_account: Method[
        Callable[
            [Union[Address, ChecksumAddress], Optional[BlockIdentifier]],
            NeonAccountData
        ]
    ] = Method(
        _neon_getAccount,
        mungers=[_get_account_munger],
    )

    def get_neon_account(
        self,
        account: Union[Address, ChecksumAddress, str],
        block_identifier: Optional[BlockIdentifier] = None,
    ) -> NeonAccountData:
        result = self._neon_get_account(account, block_identifier)

        def _to_int(_s) -> int:
            if isinstance(_s, str):
                return int(_s, 16)
            return _s
        return NeonAccountData(
            address=result.address,
            solanaAddress=result.solanaAddress,
            chainId=_to_int(result.chainId),
            transactionCount=_to_int(result.transactionCount),
            balance=_to_int(result.balance)
        )


class NeonWeb3(Web3):
    neon: Neon

    def __init__(self, provider:  Optional[BaseProvider] = None):
        super().__init__(provider)
        setattr(self, "neon", Neon(self))
