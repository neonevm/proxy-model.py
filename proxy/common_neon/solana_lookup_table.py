from __future__ import annotations

from typing import Dict, List, Optional, Tuple, Union

from solana.transaction import Transaction
from solana.publickey import PublicKey
from ..common_neon.solana_interactor import LookupTableAccountInfo


ADDRESS_LOOKUP_TABLE_ID: PublicKey = PublicKey('AddressLookupTab1e1111111111111111111111111')


class LookupTableError(RuntimeError):
    def __init__(self, *args) -> None:
        RuntimeError.__init__(self, *args)


class LookupTableInfo:
    MAX_REQUIRED_SIGN_CNT = 19
    MAX_TX_ACCOUNT_CNT = 27
    MAX_ACCOUNT_CNT = 255
    UNKNOWN_IDX = -1

    def __init__(self, table_account: PublicKey, recent_block_slot: int, nonce: int):
        self._table_account = table_account
        self._recent_block_slot = recent_block_slot
        self._nonce = nonce
        self._tx_account_dict: Dict[str, int] = {}
        self._lookup_account_dict: Dict[str, int] = {}

    @staticmethod
    def derive_lookup_table_address(signer_key: PublicKey, recent_block_slot: int) -> Tuple[PublicKey, int]:
        return PublicKey.find_program_address(
            seeds=[bytes(signer_key), recent_block_slot.to_bytes(8, "little")],
            program_id=ADDRESS_LOOKUP_TABLE_ID
        )

    @property
    def table_account(self) -> PublicKey:
        return self._table_account

    @property
    def recent_block_slot(self) -> int:
        return self._recent_block_slot

    @property
    def nonce(self) -> int:
        return self._nonce

    def get_account_list(self) -> List[PublicKey]:
        return [PublicKey(key) for key in self._lookup_account_dict.keys()]

    def get_account_idx_list(self) -> List[Tuple[PublicKey, int]]:
        return [(PublicKey(key), idx) for key, idx in self._lookup_account_dict.items()]

    def get_account_list_len(self) -> int:
        return len(self._lookup_account_dict)

    def get_tx_account_list_len(self) -> int:
        return len(self._tx_account_dict)

    def get_account_idx(self, key: Union[str, PublicKey]) -> Optional[int]:
        key = str(key)
        idx = self._tx_account_dict.get(key, None)
        if idx is None:
            idx = self._lookup_account_dict.get(key, None)

        if idx == self.UNKNOWN_IDX:
            return None
        return idx

    def is_tx_account(self, key: Union[str, PublicKey]) -> bool:
        return str(key) in self._tx_account_dict

    def init_from_legacy_transaction(self, tx: Transaction) -> None:
        assert not len(self._tx_account_dict)
        assert not len(self._lookup_account_dict)

        msg = tx.compile_message()
        if msg.header.num_required_signatures > self.MAX_REQUIRED_SIGN_CNT:
            raise LookupTableError(
                f'Too big number of signed accounts for lookup table: {msg.header.num_required_signatures}'
            )
        if len(msg.account_keys) > self.MAX_ACCOUNT_CNT:
            raise LookupTableError(f'Too big number of accounts for lookup table: {len(msg.account_keys)}')

        # required accounts should be included into the transaction
        tx_account_dict: Dict[str, int] = {
            str(key): i
            for i, key in enumerate(msg.account_keys[:msg.header.num_required_signatures])
        }

        # programs should be included into the transaction
        new_idx = msg.header.num_required_signatures
        for old_idx in [ix.program_id_index for ix in msg.instructions]:
            key = str(msg.account_keys[old_idx])
            if key not in tx_account_dict:
                tx_account_dict[key] = new_idx
                new_idx += 1

        lookup_account_dict: Dict[str, Optional[int]] = {}
        for account in msg.account_keys[msg.header.num_required_signatures:]:
            key = str(account)
            if (key not in tx_account_dict) and (key not in lookup_account_dict):
                lookup_account_dict[key] = self.UNKNOWN_IDX

        if len(lookup_account_dict) + len(tx_account_dict) != len(msg.account_keys):
            raise LookupTableError('Found duplicates in the transaction account list')

        if len(tx_account_dict) > self.MAX_TX_ACCOUNT_CNT:
            raise LookupTableError(
                'Too big number of transactions account keys: ' +
                f'{len(tx_account_dict)} > {self.MAX_TX_ACCOUNT_CNT}'
            )

        self._tx_account_dict = tx_account_dict
        self._lookup_account_dict = lookup_account_dict

    def update_from_account(self, lookup_info: LookupTableAccountInfo) -> None:
        lookup_dict: Dict[str, int] = {
            str(account): i
            for i, account in enumerate(lookup_info.account_list)
        }
        if len(lookup_dict) != len(lookup_info.account_list):
            raise LookupTableError(f'Lookup table {str(self._table_account)} has duplicates')

        for key, idx in self._lookup_account_dict.items():
            if idx != self.UNKNOWN_IDX:
                raise LookupTableError(f'Account {key} has index {idx} in the lookup table {str(self._table_account)}')
            if key not in lookup_dict:
                raise LookupTableError(f'Account {key} is not found in the lookup table {str(self._table_account)}')

        self._lookup_account_dict.update(lookup_dict)
