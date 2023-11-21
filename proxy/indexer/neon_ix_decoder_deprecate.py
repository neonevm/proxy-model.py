from typing import List, Type

from ..common_neon.neon_instruction import EvmIxCode

from ..indexer.indexed_objects import NeonAccountInfo
from ..indexer.neon_ix_decoder import (
    DummyIxDecoder,
    TxExecFromDataIxDecoder, TxExecFromAccountIxDecoder,
    TxStepFromDataIxDecoder, TxStepFromAccountIxDecoder, TxStepFromAccountNoChainIdIxDecoder,
    CancelWithHashIxDecoder
)


class OldTxExecFromDataIxDecoder(TxExecFromDataIxDecoder):
    _ix_code = EvmIxCode.OldTxExecFromData
    _is_deprecated = True


class OldTxExecFromAccountIxDecoder(TxExecFromAccountIxDecoder):
    _ix_code = EvmIxCode.OldTxExecFromAccount
    _is_deprecated = True


class OldTxStepFromAccountIxDecoder(TxStepFromAccountIxDecoder):
    _ix_code = EvmIxCode.OldTxStepFromAccount
    _is_deprecated = True


class OldTxStepFromDataIxDecoder(TxStepFromDataIxDecoder):
    _ix_code = EvmIxCode.OldTxStepFromData
    _is_deprecated = True


class OldTxStepFromAccountNoChainIdIxDecoder(TxStepFromAccountNoChainIdIxDecoder):
    _ix_code = EvmIxCode.OldTxStepFromAccountNoChainId
    _is_deprecated = True


class OldCancelWithHashIxDecoder(CancelWithHashIxDecoder):
    _ix_code = EvmIxCode.OldCancelWithHash
    _is_deprecated = True


class OldCreateAccountIxDecoder(DummyIxDecoder):
    _ix_code = EvmIxCode.OldCreateAccount
    _is_deprecated = True

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        if len(ix.ix_data) < 21:
            return self._decoding_skip(f'not enough data to get NeonAccount {len(ix.ix_data)}')

        neon_address = '0x' + ix.ix_data[1:21].hex()
        solana_address = ix.get_account(2)

        account_info = NeonAccountInfo(
            neon_address,
            0,
            solana_address,
            None,
            ix.block_slot,
            ix.sol_sig
        )
        return self._decoding_success(account_info, 'create NeonAccount')


class OldDepositIxDecoder(DummyIxDecoder):
    _ix_code = EvmIxCode.OldDeposit
    _is_deprecated = True

    def execute(self) -> bool:
        return self._decoding_success(None, 'deposit NEONs')


def get_neon_ix_decoder_deprecated_list() -> List[Type[DummyIxDecoder]]:
    ix_decoder_list: List[Type[DummyIxDecoder]] = [
        OldTxExecFromDataIxDecoder,
        OldTxExecFromAccountIxDecoder,
        OldTxStepFromDataIxDecoder,
        OldTxStepFromAccountIxDecoder,
        OldTxStepFromAccountNoChainIdIxDecoder,
        OldCreateAccountIxDecoder,
        OldDepositIxDecoder
    ]
    for IxDecoder in ix_decoder_list:
        assert IxDecoder.is_deprecated(), f"{IxDecoder.name()} is NOT deprecated!"

    return ix_decoder_list
