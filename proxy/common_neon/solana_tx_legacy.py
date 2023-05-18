from __future__ import annotations

from typing import List

import solders.transaction
import solders.message

from .solana_tx import SolTx, SolAccount, SolSig


SolLegacyMsg = solders.message.Message

_SolTxError = solders.transaction.TransactionError


class SolLegacyTx(SolTx):
    """Legacy transaction class to represent an atomic versioned transaction."""

    @property
    def message(self) -> SolLegacyMsg:
        return self._solders_legacy_tx.message

    def _sig_result_list(self) -> List[bool]:
        return self._solders_legacy_tx.verify_with_results()

    def _serialize(self) -> bytes:
        return bytes(self._solders_legacy_tx)

    def _sig(self) -> SolSig:
        return self._solders_legacy_tx.signatures[0]

    def _sign(self, *signer: SolAccount) -> None:
        self._solders_legacy_tx.sign(signer, self._solders_legacy_tx.message.recent_blockhash)

    def _clone(self) -> SolLegacyTx:
        return SolLegacyTx(self.name, self._decode_ix_list())
