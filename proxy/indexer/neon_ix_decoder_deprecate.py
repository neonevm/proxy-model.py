from typing import List, Type

from ..common_neon.neon_instruction import EvmIxCode

from ..indexer.indexed_objects import NeonAccountInfo
from ..indexer.neon_ix_decoder import DummyIxDecoder


class CreateAccount3IxDecoder(DummyIxDecoder):
    _ix_code = EvmIxCode.CreateAccountV03
    _is_deprecated = True

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        if len(ix.ix_data) < 21:
            return self._decoding_skip(f'not enough data to get NeonAccount {len(ix.ix_data)}')

        neon_account = '0x' + ix.ix_data[1:21].hex()
        pda_account = ix.get_account(2)

        account_info = NeonAccountInfo(
            neon_account,
            0,
            pda_account,
            ix.block_slot,
            ix.sol_sig
        )
        return self._decoding_success(account_info, 'create NeonAccount')


def get_neon_ix_decoder_deprecated_list() -> List[Type[DummyIxDecoder]]:
    ix_decoder_list: List[Type[DummyIxDecoder]] = [
        CreateAccount3IxDecoder,
    ]
    for IxDecoder in ix_decoder_list:
        assert IxDecoder.is_deprecated(), f"{IxDecoder.name()} is NOT deprecated!"

    return ix_decoder_list
