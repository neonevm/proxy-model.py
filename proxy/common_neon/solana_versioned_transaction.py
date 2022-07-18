from typing import List, Optional, Dict

from solana.transaction import Transaction
from solana.message import MessageHeader, CompiledInstruction

from ..common_neon.solana_versioned_message import V0Message, V0MessageArgs, MessageAddressTableLookup
from ..common_neon.solana_lookup_table import LookupTableInfo, LookupTableError


class V0Transaction(Transaction):
    """Versioned transaction class to represent an atomic versioned transaction."""

    def __init__(self, *args, address_table_lookups: Optional[List[LookupTableInfo]] = None) -> None:
        super().__init__(*args)
        self.address_table_lookups: List[LookupTableInfo] = address_table_lookups if address_table_lookups else []

    def compile_message(self) -> V0Message:
        if not isinstance(self.address_table_lookups, list):
            raise LookupTableError('Address table lookups is not a list')
        if len(self.address_table_lookups) == 0:
            raise LookupTableError('No address lookup tables')
        for lookup in self.address_table_lookups:
            if not isinstance(lookup, LookupTableInfo):
                raise LookupTableError(f'Bad type {type(lookup)} for address lookup table')

        old_msg = super().compile_message()

        key_list_len = len(old_msg.account_keys)
        start_readonly_idx = key_list_len - old_msg.header.num_readonly_unsigned_accounts

        tx_idx_dict: Dict[int, int] = {}
        full_idx_dict: Dict[int, int] = {}

        # Validate that first account table has transaction account list and others don't have it
        for i, lookup in enumerate(self.address_table_lookups):
            if i == 0 and lookup.get_tx_account_list_len() == 0:
                raise LookupTableError('First lookup table does not have transaction account list')
            elif i != 0 and lookup.get_tx_account_list_len() != 0:
                raise LookupTableError(f'The lookup table {i} has transaction account list')

        tx_account_list_len = self.address_table_lookups[0].get_tx_account_list_len()

        # Build maps for old-index <-> new-index
        for old_idx, key in enumerate(old_msg.account_keys):
            base_idx = tx_account_list_len
            is_tx_key = False
            new_idx: Optional[int] = None
            for lookup in self.address_table_lookups:
                new_idx = lookup.get_account_idx(key)
                if new_idx is not None:
                    is_tx_key = lookup.is_tx_account(key)
                    if not is_tx_key:
                        new_idx += base_idx
                    break
                else:
                    base_idx += lookup.get_account_list_len()
            if new_idx is None:
                raise LookupTableError(f'Account {key} is absent in lookup tables')
            prev_new_idx = full_idx_dict.get(old_idx, None)
            if prev_new_idx is not None:
                raise LookupTableError(f'Account {key} has duplicate index {prev_new_idx} != {new_idx}')
            full_idx_dict[old_idx] = new_idx
            if is_tx_key:
                tx_idx_dict[new_idx] = old_idx

        if len(tx_idx_dict) > LookupTableInfo.MAX_TX_ACCOUNT_CNT:
            raise LookupTableError(
                'Too big number of transactions account keys with lookup tables: ' +
                f'{len(tx_idx_dict)} > {LookupTableInfo.MAX_TX_ACCOUNT_CNT}'
            )

        # Build static transaction's account list
        num_readonly_unsigned_accounts = 0
        account_key_list: List[str] = []
        for idx in range(len(tx_idx_dict)):
            old_idx = tx_idx_dict.get(idx, None)
            if old_idx is None:
                raise LookupTableError(f'No account for static transaction keys with index {idx}')
            account_key_list.append(old_msg.account_keys[old_idx])
            if old_idx >= start_readonly_idx:
                num_readonly_unsigned_accounts += 1

        # Update compiled instructions with new indexes
        ix_list: List[CompiledInstruction] = []
        for old_ix in old_msg.instructions:
            ix_prg_idx = full_idx_dict.get(old_ix.program_id_index, None)
            if ix_prg_idx is None:
                raise LookupTableError(f'Program with idx {old_ix.program_id_index} does not exist in account list')
            ix_account_list: List[int] = []
            for old_idx in old_ix.accounts:
                new_idx = full_idx_dict.get(old_idx, None)
                if new_idx is None:
                    raise LookupTableError(f'Account with idx {old_idx} does not exist in account list')
                ix_account_list.append(new_idx)
            ix_list.append(
                CompiledInstruction(
                    program_id_index=ix_prg_idx,
                    data=old_ix.data,
                    accounts=ix_account_list
                )
            )

        # Build lookups list
        old_account_key_dict = {str(key): idx for idx, key in enumerate(old_msg.account_keys)}
        lookup_list: List[MessageAddressTableLookup] = []
        for lookup in self.address_table_lookups:
            writable_idx_list: List[int] = []
            readonly_idx_list: List[int] = []
            ll = lookup.get_account_idx_list()
            for key, idx in ll:
                old_idx = old_account_key_dict.get(str(key), None)
                if old_idx is None:
                    continue
                if old_idx >= start_readonly_idx:
                    readonly_idx_list.append(idx)
                else:
                    writable_idx_list.append(idx)

            if len(writable_idx_list) == 0 and len(readonly_idx_list) == 0:
                raise LookupTableError(f'Include not-used lookup table {str(lookup.table_account)}')

            lookup_list.append(
                MessageAddressTableLookup(
                    account_key=lookup.table_account,
                    writable_indexes=writable_idx_list,
                    readonly_indexes=readonly_idx_list
                )
            )

        return V0Message(
            V0MessageArgs(
                header=MessageHeader(
                    num_required_signatures=old_msg.header.num_required_signatures,
                    num_readonly_signed_accounts=old_msg.header.num_readonly_signed_accounts,
                    num_readonly_unsigned_accounts=num_readonly_unsigned_accounts,
                ),
                account_keys=account_key_list,
                instructions=ix_list,
                recent_blockhash=old_msg.recent_blockhash,
                address_table_lookups=lookup_list
            )
        )
