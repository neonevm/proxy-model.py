from __future__ import annotations

from typing import List, Dict, Optional, Sequence, Union

import solders.hash
import solders.instruction
import solders.message
import solders.transaction

from ..common_neon.errors import ALTError
from ..common_neon.solana_alt import ALTInfo
from ..common_neon.solana_alt_list_filter import ALTListFilter
from ..common_neon.solana_transaction import SolTxIx, SolPubKey, SolBlockhash, SolSignature, SolAccount, SolLegacyTx


SoldersV0Tx = solders.transaction.VersionedTransaction
SoldersV0Msg = solders.message.MessageV0
SoldersMsgALT = solders.message.MessageAddressTableLookup
SoldersMsgHdr = solders.message.MessageHeader
SoldersCompiledIx = solders.instruction.CompiledInstruction
SoldersHash = solders.hash.Hash


class SolV0Tx:
    """Versioned transaction class to represent an atomic versioned transaction."""

    def __init__(self, address_table_lookups: Sequence[ALTInfo],
                 instructions: Optional[Sequence[SolTxIx]] = None) -> None:
        self._solders_tx = SoldersV0Tx.default()
        self._legacy_tx = SolLegacyTx(instructions=instructions)
        self._alt_list = list(address_table_lookups)
        self._is_signed = False

    @property
    def recent_blockhash(self) -> Optional[SolBlockhash]:
        return self._legacy_tx.recent_blockhash

    @recent_blockhash.setter
    def recent_blockhash(self, blockhash: Optional[SolBlockhash]) -> None:
        self._is_signed = False
        self._legacy_tx.recent_blockhash = blockhash

    def signature(self) -> SolSignature:
        if not self._is_signed:
            raise AttributeError("transaction has not been signed")

        return self._solders_tx.signatures[0]

    def serialize(self) -> bytes:
        if not self._is_signed:
            raise AttributeError("transaction has not been signed")

        return bytes(self._solders_tx)

    def add(self, *args: Union[SolLegacyTx, SolTxIx]) -> SolV0Tx:
        self._is_signed = False
        self._legacy_tx.add(*args)
        return self

    def sign(self, signer: SolAccount) -> None:
        legacy_msg = self._legacy_tx.message
        alt_filter = ALTListFilter(legacy_msg)

        rw_key_set = alt_filter.filter_rw_account_key_set()
        ro_key_set = alt_filter.filter_ro_account_key_set()

        # Account indexes must index into the list of addresses
        # constructed from the concatenation of three key lists:
        #   1) message `account_keys`
        #   2) ordered list of keys loaded from `writable` lookup table indexes
        #   3) ordered list of keys loaded from `readable` lookup table indexes

        rw_key_list: List[str] = []
        ro_key_list: List[str] = []

        # Build the lookup list in the V0 transaction
        alt_msg_list: List[SoldersMsgALT] = []
        for alt_info in self._alt_list:
            rw_idx_list: List[int] = []
            ro_idx_list: List[int] = []
            for idx, key in enumerate(alt_info.account_key_list):
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

            alt_msg_list.append(
                SoldersMsgALT(
                    account_key=alt_info.table_account.to_solders(),
                    writable_indexes=bytes(rw_idx_list),
                    readonly_indexes=bytes(ro_idx_list),
                )
            )

        if not len(alt_msg_list):
            raise ALTError(f'No account lookups to include into V0Transaction')

        # Set the positions of the static transaction accounts
        signed_key_cnt = legacy_msg.header.num_required_signatures
        tx_key_list = alt_filter.tx_account_key_list
        tx_ro_unsigned_account_key_cnt = alt_filter.tx_unsigned_account_key_cnt + len(ro_key_set)
        signed_tx_key_list, ro_tx_key_list = tx_key_list[:signed_key_cnt], tx_key_list[signed_key_cnt:]

        tx_key_list = (
            signed_tx_key_list +
            # If the tx has an additional account key, which is not listed in the address_table_lookups
            #   then add it to the static part of the tx account list
            [SolPubKey(key) for key in rw_key_set] +
            [SolPubKey(key) for key in ro_key_set] +
            ro_tx_key_list
        )

        key_new_idx_dict: Dict[str, int] = {str(key): idx for idx, key in enumerate(tx_key_list)}
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
                raise ALTError(f'Account {key} does not exist in lookup accounts')
            old_new_idx_dict[old_idx] = new_idx

        # Update compiled instructions with new indexes
        new_ix_list: List[SoldersCompiledIx] = []
        for old_ix in legacy_msg.instructions:
            # Get the new index for the program
            old_prog_idx = old_ix.program_id_index
            new_prog_idx = old_new_idx_dict.get(old_prog_idx, None)
            if new_prog_idx is None:
                raise ALTError(f'Program with idx {old_prog_idx} does not exist in account list')

            # Get new indexes for instruction accounts
            new_ix_acct_list: List[int] = []
            for old_idx in old_ix.accounts:
                new_idx = old_new_idx_dict.get(old_idx, None)
                if new_idx is None:
                    raise ALTError(f'Account with idx {old_idx} does not exist in account list')
                new_ix_acct_list.append(new_idx)

            new_ix_list.append(
                SoldersCompiledIx(
                    program_id_index=new_prog_idx,
                    data=old_ix.data,
                    accounts=bytes(new_ix_acct_list)
                )
            )

        hdr = SoldersMsgHdr(
            num_required_signatures=legacy_msg.header.num_required_signatures,
            num_readonly_signed_accounts=legacy_msg.header.num_readonly_signed_accounts,
            num_readonly_unsigned_accounts=tx_ro_unsigned_account_key_cnt
        )

        msg = SoldersV0Msg(
            header=hdr,
            account_keys=[key.to_solders() for key in tx_key_list],
            recent_blockhash=SoldersHash.from_string(legacy_msg.recent_blockhash),
            instructions=new_ix_list,
            address_table_lookups=alt_msg_list
        )

        self._solders_tx = SoldersV0Tx(msg, [signer.to_solders()])
