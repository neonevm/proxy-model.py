from __future__ import annotations

import abc
import os

import base58
from logged_groups import logged_group
from solana.publickey import PublicKey
from solana.transaction import AccountMeta

from ..common_neon.address import accountWithSeed
from ..common_neon.compute_budget import TransactionWithComputeBudget
from ..common_neon.constants import NEON_ACCOUNT_BASE_SIZE


class NeonTxStage(metaclass=abc.ABCMeta):
    NAME = 'UNKNOWN'

    def __init__(self, sender):
        self.s = sender
        self.tx = TransactionWithComputeBudget()

    def _is_empty(self):
        return not len(self.tx.signatures)

    @abc.abstractmethod
    def build(self):
        pass


@logged_group("neon.Proxy")
class NeonCancelTxStage(NeonTxStage, abc.ABC):
    NAME = 'cancelWithNonce'

    def __init__(self, sender, account: PublicKey):
        NeonTxStage.__init__(self, sender)
        self._account = account
        self._storage = self.s.solana.get_storage_account_info(account)

    def _cancel_ix(self):
        key_list = []
        for is_writable, account in self._storage.account_list:
            key_list.append(AccountMeta(pubkey=account, is_signer=False, is_writable=is_writable))

        return self.s.builder.make_cancel_instruction(storage=self._account,
                                                      nonce=self._storage.nonce,
                                                      cancel_keys=key_list)

    def build(self):
        assert self._is_empty()
        assert self._storage is not None

        self.debug(f'Cancel transaction in storage account {str(self._account)}')
        self.tx.add(self._cancel_ix())


class NeonCreateAccountWithSeedStage(NeonTxStage, abc.ABC):
    def __init__(self, sender):
        NeonTxStage.__init__(self, sender)
        self._seed = bytes()
        self._seed_base = bytes()
        self.sol_account = None
        self.size = 0
        self.balance = 0

    def _init_sol_account(self):
        assert len(self._seed_base) > 0

        self._seed = base58.b58encode(self._seed_base)
        self.sol_account = accountWithSeed(self.s.operator_key, self._seed)

    def _create_account_with_seed(self):
        assert len(self._seed) > 0
        assert self.size > 0
        assert self.balance > 0

        return self.s.builder.create_account_with_seed_instruction(self.sol_account, self._seed, self.balance, self.size)


@logged_group("neon.Proxy")
class NeonAirdropTxStage(NeonTxStage):
    NAME = 'airdropNeon'

    def __init__(self, sender, account_desc):
        NeonTxStage.__init__(self, sender)
        self.address = account_desc["address"]
        self.amount = account_desc["amount"]
        self.balance = self.s.solana.get_multiple_rent_exempt_balances_for_size([NEON_ACCOUNT_BASE_SIZE])[0]

    def build(self):
        assert self._is_empty()
        self.debug(f'Airdrop {self.address}: (amount {self.amount})')
        instructions = self.s.builder.make_airdrop_neon_tokens_instructions(self.s.solana, self.address, self.amount)
        for instruction in instructions:
            self.tx.add(instruction)


@logged_group("neon.Proxy")
class NeonCreateERC20TxStage(NeonTxStage, abc.ABC):
    NAME = 'createERC20Account'

    def __init__(self, sender, token_account):
        NeonTxStage.__init__(self, sender)
        self._token_account = token_account
        self.size = 124
        self.balance = 0

    def _create_erc20_account(self):
        assert self.balance > 0
        return self.s.builder.make_erc20token_account_instruction(self._token_account)

    def build(self):
        assert self._is_empty()

        self.debug(f'Create ERC20 token account: ' +
                   f'key {self._token_account["key"]}, ' +
                   f'owner: {self._token_account["owner"]}, ' +
                   f'contact: {self._token_account["contract"]}, ' +
                   f'mint: {self._token_account["mint"]}')

        self.tx.add(self._create_erc20_account())
