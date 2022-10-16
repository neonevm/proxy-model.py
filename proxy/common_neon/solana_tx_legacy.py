from __future__ import annotations

import solana.message

from .solana_tx import SolTx, SolAccount, SolSignature


SolLegacyMsg = solana.message.Message


class SolLegacyTx(SolTx):
    """Legacy transaction class to represent an atomic versioned transaction."""

    @property
    def message(self) -> SolLegacyMsg:
        return self._tx.compile_message()

    def _serialize(self) -> bytes:
        return self._tx.serialize()

    def _signature(self) -> SolSignature:
        return self._tx.signature()

    def _sign(self, signer: SolAccount) -> None:
        self._tx.sign(signer)
