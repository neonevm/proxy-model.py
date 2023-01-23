from typing import List, Type

from ..indexer.neon_ix_decoder import DummyIxDecoder


def get_neon_ix_decoder_deprecated_list() -> List[Type[DummyIxDecoder]]:
    ix_decoder_list: List[Type[DummyIxDecoder]] = []
    for IxDecoder in ix_decoder_list:
        assert IxDecoder.is_deprecated(), f"{IxDecoder.name()} is NOT deprecated!"

    return ix_decoder_list
