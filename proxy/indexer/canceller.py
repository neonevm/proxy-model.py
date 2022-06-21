import traceback

from logged_groups import logged_group
from typing import  Dict, Tuple, List
from solana.transaction import AccountMeta
from solana.publickey import PublicKey

from ..common_neon.neon_instruction import NeonInstruction
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.solana_tx_list_sender import SolTxListSender
from ..common_neon.compute_budget import TransactionWithComputeBudget
from ..common_neon.environment_utils import get_solana_accounts


@logged_group("neon.Indexer")
class Canceller:
    def __init__(self, solana: SolanaInteractor):
        self.solana = solana
        self.waiter = None
        self._signer = get_solana_accounts()[0]
        self._operator = self._signer.public_key()
        self._builder = NeonInstruction(self._operator)

    def unlock_accounts(self, blocked_storage_dict: Dict[str, Tuple[int, List[Tuple[bool, str]]]]) -> None:
        tx_list: List[TransactionWithComputeBudget] = []
        for storage, storage_account_tuple in blocked_storage_dict.items():
            (nonce, blocked_account_list) = storage_account_tuple
            key_list: List[AccountMeta] = []
            for is_writable, acc in blocked_account_list:
                key_list.append(AccountMeta(pubkey=PublicKey(acc), is_signer=False, is_writable=is_writable))

            self._builder.init_iterative(storage, None, 0)

            tx = TransactionWithComputeBudget()
            tx.add(self._builder.make_cancel_instruction(nonce=nonce, cancel_keys=key_list))
            tx_list.append(tx)

        if not len(tx_list):
            return

        self.debug(f"Send Cancel: {len(tx_list)}")

        try:
            SolTxListSender(self, tx_list, f'CancelWithNonce({len(tx_list)})').send(self._signer)
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.warning('Exception on submitting transaction. ' +
                         f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')
