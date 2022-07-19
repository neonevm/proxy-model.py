from typing import List, Dict

from solana.transaction import Transaction
from solana.message import MessageHeader, CompiledInstruction

from ..common_neon.solana_v0_message import V0Message, V0MessageArgs, MessageAddressTableLookup
from ..common_neon.solana_v0_transaction_builder import V0TransactionBuilder, V0TransactionError
from ..common_neon.solana_account_lookup_table import AccountLookupTableInfo


class V0Transaction(Transaction):
    """Versioned transaction class to represent an atomic versioned transaction."""

    def __init__(self, *args, address_table_lookups: List[AccountLookupTableInfo] = None) -> None:
        super().__init__(*args)

        if not isinstance(address_table_lookups, list):
            raise V0TransactionError('Address table lookups should be a list')
        elif len(address_table_lookups) == 0:
            raise V0TransactionError('No address lookup tables')

        for lookup in address_table_lookups:
            if not isinstance(lookup, AccountLookupTableInfo):
                raise V0TransactionError(f'Bad type {type(lookup)} for address lookup table')

        self.address_table_lookups: List[AccountLookupTableInfo] = address_table_lookups

    def compile_message(self) -> V0Message:
        legacy_msg = super().compile_message()
        builder = V0TransactionBuilder(legacy_msg)

        tx_key_list = builder.tx_account_key_list
        rw_key_set = builder.build_rw_account_key_set()
        ro_key_set = builder.build_ro_account_key_set()

        # Account indexes must index into the list of addresses
        # constructed from the concatenation of three key lists:
        #   1) message `account_keys`
        #   2) ordered list of keys loaded from `writable` lookup table indexes
        #   3) ordered list of keys loaded from `readable` lookup table indexes

        # Set the positions of the static transaction accounts
        key_new_idx_dict: Dict[str, int] = {str(key): idx for idx, key in enumerate(tx_key_list)}

        rw_key_list: List[str] = []
        ro_key_list: List[str] = []

        # Build the lookup list in the V0 transaction
        lookup_list: List[MessageAddressTableLookup] = []
        for lookup in self.address_table_lookups:
            rw_idx_list: List[int] = []
            ro_idx_list: List[int] = []
            for idx, key in enumerate(lookup.account_key_list):
                key = str(key)
                if key in rw_key_set:
                    rw_idx_list.append(idx)
                    rw_key_list.append(key)
                    rw_key_set.discard(key)
                elif key in ro_key_set:
                    ro_idx_list.append(idx)
                    ro_key_list.append(key)
                    ro_key_set.discard(key)

            if len(rw_idx_list) == len(ro_idx_list) == 0:
                continue

            lookup_list.append(
                MessageAddressTableLookup(
                    account_key=lookup.table_account,
                    writable_indexes=rw_idx_list,
                    readonly_indexes=ro_idx_list,
                )
            )

        if not len(lookup_list):
            raise V0TransactionError(f'No account lookups to include into V0Transaction')

        for key in rw_key_list:
            key_new_idx_dict[key] = len(key_new_idx_dict)
        for key in ro_key_list:
            key_new_idx_dict[key] = len(key_new_idx_dict)

        # Build relations between old and new indexes
        old_new_idx_dict: Dict[int, int] = {}
        for old_idx, key in enumerate(legacy_msg.account_keys):
            key = str(key)
            new_idx = key_new_idx_dict.get(key, None)
            if new_idx is None:
                raise V0TransactionError(f'Account {key} does not exist in lookup accounts')
            old_new_idx_dict[old_idx] = new_idx

        # Update compiled instructions with new indexes
        ix_list: List[CompiledInstruction] = []
        for old_ix in legacy_msg.instructions:
            # Get the new index for the program
            ix_prg_idx = old_new_idx_dict.get(old_ix.program_id_index, None)
            if ix_prg_idx is None:
                raise V0TransactionError(f'Program with idx {old_ix.program_id_index} does not exist in account list')

            # Get new indexes for instruction accounts
            ix_account_list: List[int] = []
            for old_idx in old_ix.accounts:
                new_idx = old_new_idx_dict.get(old_idx, None)
                if new_idx is None:
                    raise V0TransactionError(f'Account with idx {old_idx} does not exist in account list')
                ix_account_list.append(new_idx)

            ix_list.append(
                CompiledInstruction(
                    program_id_index=ix_prg_idx,
                    data=old_ix.data,
                    accounts=ix_account_list
                )
            )

        return V0Message(
            V0MessageArgs(
                header=MessageHeader(
                    num_required_signatures=legacy_msg.header.num_required_signatures,
                    num_readonly_signed_accounts=legacy_msg.header.num_readonly_signed_accounts,
                    num_readonly_unsigned_accounts=builder.tx_unsigned_account_key_cnt,
                ),
                account_keys=[str(key) for key in tx_key_list],
                instructions=ix_list,
                recent_blockhash=legacy_msg.recent_blockhash,
                address_table_lookups=lookup_list
            )
        )
