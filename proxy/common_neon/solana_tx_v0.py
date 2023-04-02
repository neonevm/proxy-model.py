from __future__ import annotations

from typing import List, Dict, Optional, Sequence

import solders.instruction
import solders.message
import solders.transaction

from .solana_tx import SolTx, SolSig, SolAccount, SolPubKey, SolTxIx

from .errors import ALTError
from .solana_alt import ALTInfo
from .solana_alt_list_filter import ALTListFilter


_SoldersMsgALT = solders.message.MessageAddressTableLookup
_SoldersCompiledIx = solders.instruction.CompiledInstruction
_SoldersMsgHdr = solders.message.MessageHeader
_SoldersMsgV0 = solders.message.MessageV0
_SoldersTxV0 = solders.transaction.VersionedTransaction


class SolV0Tx(SolTx):
    """Versioned transaction class to represent an atomic versioned transaction."""

    def __init__(self, name: str,
                 ix_list: Optional[Sequence[SolTxIx]],
                 alt_info_list: Sequence[ALTInfo]) -> None:
        super().__init__(name=name, ix_list=ix_list)
        self._solders_v0_tx = _SoldersTxV0.default()
        self._alt_info_list = list(alt_info_list)
        assert len(self._alt_info_list) > 0

    def _sig(self) -> SolSig:
        return self._solders_v0_tx.signatures[0]

    def _sig_result_list(self) -> List[bool]:
        return self._solders_v0_tx.verify_with_results()

    def _serialize(self) -> bytes:
        return bytes(self._solders_v0_tx)

    def _sign(self, signer: SolAccount) -> None:
        legacy_msg = self._solders_legacy_tx.message
        alt_filter = ALTListFilter(legacy_msg)

        rw_key_set = alt_filter.filter_rw_account_key_set()
        ro_key_set = alt_filter.filter_ro_account_key_set()

        # Account indexes must index into the list of addresses
        # constructed from the concatenation of three key lists:
        #   1) message `account_keys`
        #   2) ordered list of keys loaded from `writable` lookup table indexes
        #   3) ordered list of keys loaded from `readable` lookup table indexes

        rw_key_list: List[str] = list()
        ro_key_list: List[str] = list()

        # Build the lookup list in the V0 transaction
        alt_msg_list: List[_SoldersMsgALT] = list()
        for alt_info in self._alt_info_list:
            rw_idx_list: List[int] = list()
            ro_idx_list: List[int] = list()
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
                _SoldersMsgALT(
                    account_key=alt_info.table_account,
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
            [SolPubKey.from_string(key) for key in rw_key_set] +
            [SolPubKey.from_string(key) for key in ro_key_set] +
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
        new_ix_list: List[_SoldersCompiledIx] = []
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
                _SoldersCompiledIx(
                    program_id_index=new_prog_idx,
                    data=old_ix.data,
                    accounts=bytes(new_ix_acct_list)
                )
            )

        hdr = _SoldersMsgHdr(
            num_required_signatures=legacy_msg.header.num_required_signatures,
            num_readonly_signed_accounts=legacy_msg.header.num_readonly_signed_accounts,
            num_readonly_unsigned_accounts=tx_ro_unsigned_account_key_cnt
        )

        msg = _SoldersMsgV0(
            header=hdr,
            account_keys=[key for key in tx_key_list],
            recent_blockhash=legacy_msg.recent_blockhash,
            instructions=new_ix_list,
            address_table_lookups=alt_msg_list
        )

        self._solders_v0_tx = _SoldersTxV0(msg, [signer])

    def _clone(self) -> SolV0Tx:
        return SolV0Tx(self._name, self._decode_ix_list(), self._alt_info_list)
