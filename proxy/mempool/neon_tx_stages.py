from __future__ import annotations

import abc
import os
import base58

from typing import Optional, Dict, Any
from logged_groups import logged_group

from ..common_neon.solana_transaction import SolLegacyTx, SolTxIx, SolPubKey
from ..common_neon.config import Config
from ..common_neon.address import accountWithSeed
from ..common_neon.constants import ACCOUNT_SEED_VERSION
from ..common_neon.neon_instruction import NeonIxBuilder


@logged_group("neon.MemPool")
class NeonTxStage(abc.ABC):
    name = 'UNKNOWN'

    def __init__(self, builder: NeonIxBuilder):
        self._builder = builder
        self._size = 0
        self._balance = 0
        self.tx = SolLegacyTx()

    def _is_empty(self) -> bool:
        return not len(self.tx.signatures)

    @abc.abstractmethod
    def build(self) -> None:
        pass

    @property
    def size(self) -> int:
        assert self._size > 0
        return self._size

    def set_balance(self, value: int) -> None:
        assert value > 0
        self._balance = value

    def has_balance(self) -> bool:
        return self._balance > 0

    @property
    def balance(self):
        assert self.has_balance()
        return self._balance


class NeonCreateAccountWithSeedStage(NeonTxStage, abc.ABC):
    def __init__(self, builder: NeonIxBuilder):
        super().__init__(builder)
        self._seed = bytes()
        self._seed_base = bytes()
        self._sol_account: Optional[SolPubKey] = None

    def _init_sol_account(self) -> None:
        assert len(self._seed_base) > 0

        self._seed = base58.b58encode(self._seed_base)
        self._sol_account = accountWithSeed(self._builder.operator_account, self._seed)

    @property
    def sol_account(self) -> SolPubKey:
        assert self._sol_account is not None
        return self._sol_account

    def _create_account_with_seed(self) -> SolTxIx:
        assert len(self._seed) > 0

        return self._builder.make_create_account_with_seed_ix(self.sol_account, self._seed, self.balance, self.size)


class NeonCreateAccountTxStage(NeonTxStage):
    name = 'createNeonAccount'

    def __init__(self, builder: NeonIxBuilder, account_desc: Dict[str, Any]):
        super().__init__(builder)
        self._address = account_desc['address']
        self._size = 95

    def _create_account(self) -> SolTxIx:
        assert self.has_balance()
        return self._builder.make_create_eth_account_ix(self._address)

    def build(self) -> None:
        assert self._is_empty()
        self.debug(f'Create user account {self._address}')
        self.tx.add(self._create_account())


class NeonCreateContractTxStage(NeonCreateAccountWithSeedStage):
    name = 'createNeonContract'

    def __init__(self, builder: NeonIxBuilder, account_desc: Dict[str, Any]):
        super().__init__(builder)
        self._account_desc = account_desc
        self._address = account_desc["address"]
        self._seed_base = ACCOUNT_SEED_VERSION + bytes.fromhex(self._address[2:])
        self._init_sol_account()
        self._account_desc['contract'] = self.sol_account
        self._size = account_desc['code_size'] + Config().contract_extra_space  # will be removed ..

    def _create_account(self) -> SolTxIx:
        assert self.has_balance()
        return self._builder.make_create_eth_account_ix(self._address, self.sol_account)

    def build(self) -> None:
        assert self._is_empty()

        self.debug(f'Create contact {self._address}: {self.sol_account} (size {self.size})')

        self.tx.add(self._create_account_with_seed())
        self.tx.add(self._create_account())


class NeonResizeContractTxStage(NeonCreateAccountWithSeedStage):
    name = 'resizeNeonContract'

    def __init__(self, builder: NeonIxBuilder, account_desc: Dict[str, Any]):
        super().__init__(builder)
        self._account_desc = account_desc
        self._seed_base = ACCOUNT_SEED_VERSION + os.urandom(20)
        self._init_sol_account()
        # Replace the old code account with the new code account
        self._old_sol_account = account_desc['contract']
        account_desc['contract'] = self.sol_account
        self._size = account_desc['code_size'] + Config().contract_extra_space  # will be removed ..

    def _resize_account(self) -> SolTxIx:
        assert self.has_balance()
        account = self._account_desc['account']
        return self._builder.make_resize_ix(account, self._old_sol_account, self.sol_account, self._seed)

    def build(self) -> None:
        assert self._is_empty()

        self.debug(
            f'Resize contact {self._account_desc["address"]}: ' +
            f'{self._old_sol_account} (size {self._account_desc["code_size_current"]}) -> ' +
            f'{self.sol_account} (size {self.size})'
        )

        self.tx.add(self._create_account_with_seed())
        self.tx.add(self._resize_account())


class NeonCreateHolderAccountStage(NeonCreateAccountWithSeedStage):
    name = 'createHolderAccount'

    def __init__(self, builder: NeonIxBuilder, seed: bytes, size: int, balance: int):
        super().__init__(builder)
        self._seed = seed
        self._size = size
        self.set_balance(balance)
        self._init_sol_account()

    def _init_sol_account(self):
        assert len(self._seed) > 0
        self._sol_account = accountWithSeed(self._builder.operator_account, self._seed)

    def build(self):
        assert self._is_empty()

        self.debug(f'Create perm account {self.sol_account}')
        self.tx.add(self._create_account_with_seed())
        self.tx.add(self._builder.create_holder_ix(self.sol_account))


class NeonDeleteHolderAccountStage(NeonTxStage):
    name = 'deleteHolderAccount'

    def __init__(self, builder: NeonIxBuilder, seed: bytes):
        super().__init__(builder)
        self._sol_account: Optional[SolPubKey] = None
        self._seed = seed
        self._init_sol_account()

    def _init_sol_account(self):
        assert len(self._seed) > 0
        self._sol_account = accountWithSeed(self._builder.operator_account, self._seed)

    def _delete_account(self):
        return self._builder.make_delete_holder_ix(self._sol_account)

    def build(self):
        assert self._is_empty()

        self.debug(f'Delete holder account {self._sol_account}')
        self.tx.add(self._delete_account())
