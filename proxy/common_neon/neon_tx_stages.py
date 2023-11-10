from __future__ import annotations

import abc
import logging

from .neon_instruction import NeonIxBuilder
from .solana_tx import SolPubKey
from .solana_tx_legacy import SolLegacyTx

from ..neon_core_api.neon_layouts import NeonAccountInfo


LOG = logging.getLogger(__name__)


class NeonTxStage(abc.ABC):
    name = 'UNKNOWN'

    def __init__(self, ix_builder: NeonIxBuilder):
        self._ix_builder = ix_builder
        self.tx = SolLegacyTx(name=self.name, ix_list=None)

    def _is_empty(self) -> bool:
        return self.tx.is_empty()

    @abc.abstractmethod
    def build(self) -> None:
        pass


class NeonCreateAccountTxStage(NeonTxStage):
    name = 'createNeonAccount'

    def __init__(self, builder: NeonIxBuilder, neon_account_info: NeonAccountInfo):
        super().__init__(builder)
        self._neon_acct_info = neon_account_info

    def build(self) -> None:
        assert self._is_empty()
        LOG.debug(f'Create user account {self._neon_acct_info.neon_address}:{self._neon_acct_info.chain_id}')
        self.tx.add(self._ix_builder.make_create_neon_account_ix(self._neon_acct_info))


class NeonCreateHolderAccountStage(NeonTxStage):
    name = 'createHolderAccount'

    def __init__(self, builder: NeonIxBuilder, sol_acct: SolPubKey, seed: bytes, size: int, balance: int):
        super().__init__(builder)
        self._sol_acct = sol_acct
        self._seed = seed
        self._size = size
        self._balance = balance

    def build(self):
        assert self._is_empty()

        LOG.debug(f'Create perm account {str(self._sol_acct)}')

        create_ix = self._ix_builder.make_create_account_with_seed_ix(
            self._sol_acct, self._seed, self._balance, self._size
        )
        holder_ix = self._ix_builder.create_holder_ix(self._sol_acct, self._seed)
        self.tx.add(create_ix)
        self.tx.add(holder_ix)


class NeonDeleteHolderAccountStage(NeonTxStage):
    name = 'deleteHolderAccount'

    def __init__(self, builder: NeonIxBuilder, sol_acct: SolPubKey):
        super().__init__(builder)
        self._sol_acct = sol_acct

    def _delete_account(self):
        return self._ix_builder.make_delete_holder_ix(self._sol_acct)

    def build(self):
        assert self._is_empty()

        LOG.debug(f'Delete holder account {str(self._sol_acct)}')
        self.tx.add(self._delete_account())
