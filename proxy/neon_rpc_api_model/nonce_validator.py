from __future__ import annotations

from ..common_neon.errors import EthereumError, NonceTooLowError
from ..common_neon.utils.eth_proto import NeonTx
from ..common_neon.solana_interactor import SolInteractor


class NeonTxNonceValidator:
    max_u64 = 2 ** 64 - 1

    def __init__(self, solana: SolInteractor, tx: NeonTx):
        self._solana = solana
        self._tx = tx

    def precheck(self) -> None:
        tx_nonce = int(self._tx.nonce)
        state_tx_cnt = self._solana.get_state_tx_cnt(self._tx.sender)
        if self.max_u64 in (state_tx_cnt, tx_nonce):
            sender = self._tx.hex_sender
            raise EthereumError(
                code=NonceTooLowError.eth_error_code,
                message=f'nonce has max value: address {sender}, tx: {tx_nonce} state: {state_tx_cnt}'
            )

        NonceTooLowError.raise_if_error(self._tx.hex_sender, tx_nonce, state_tx_cnt)
