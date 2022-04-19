import traceback

from logged_groups import logged_group
from solana.transaction import AccountMeta
from proxy.common_neon.neon_instruction import NeonInstruction
from proxy.common_neon.solana_interactor import SolanaInteractor
from proxy.common_neon.solana_tx_list_sender import SolTxListSender
from proxy.common_neon.compute_budget import TransactionWithComputeBudget
from proxy.environment import get_solana_accounts


@logged_group("neon.Indexer")
class Canceller:
    def __init__(self, solana: SolanaInteractor):
        # Initialize user account
        self.signer = get_solana_accounts()[0]
        self.solana = solana
        self.waiter = None
        self._operator = self.signer.public_key()
        self.builder = NeonInstruction(self._operator)

    def unlock_accounts(self, blocked_storages):
        tx_list = []
        for storage, tx_accounts in blocked_storages.items():
            (neon_tx, blocked_accounts) = tx_accounts
            if blocked_accounts is None:
                self.error(f"Empty blocked accounts for the Neon tx {neon_tx}.")
            else:
                keys = []
                for is_writable, acc in blocked_accounts:
                    keys.append(AccountMeta(pubkey=acc, is_signer=False, is_writable=is_writable))

                self.builder.init_iterative(storage, None, 0)

                tx = TransactionWithComputeBudget()
                tx.add(self.builder.make_cancel_instruction(nonce=int(neon_tx.nonce[2:], 16), cancel_keys=keys))
                tx_list.append(tx)

        if not len(tx_list):
            return

        self.debug(f"Send Cancel: {len(tx_list)}")

        try:
            SolTxListSender(self, tx_list, f'CancelWithNonce({len(tx_list)})').send(self.signer)
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.warning('Exception on submitting transaction. ' +
                         f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')
