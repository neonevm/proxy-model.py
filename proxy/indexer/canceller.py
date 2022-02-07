
import traceback
from solana.publickey import PublicKey
from solana.rpc.api import Client
from solana.transaction import AccountMeta
from spl.token.instructions import get_associated_token_address
from proxy.common_neon.constants import SYSVAR_INSTRUCTION_PUBKEY
from proxy.common_neon.neon_instruction import NeonInstruction
from proxy.common_neon.solana_interactor import SolanaInteractor
from proxy.environment import ETH_TOKEN_MINT_ID, SOLANA_URL, get_solana_accounts
from ..environment import SOLANA_URL, EVM_LOADER_ID, ETH_TOKEN_MINT_ID, get_solana_accounts
from ..common_neon.constants import SYSVAR_INSTRUCTION_PUBKEY, INCINERATOR_PUBKEY, KECCAK_PROGRAM
from solana.sysvar import SYSVAR_CLOCK_PUBKEY, SYSVAR_RENT_PUBKEY
from solana.system_program import SYS_PROGRAM_ID
from spl.token.constants import TOKEN_PROGRAM_ID
from logged_groups import logged_group


@logged_group("neon.Indexer")
class Canceller:
    readonly_accs = [
        PublicKey(EVM_LOADER_ID),
        PublicKey(ETH_TOKEN_MINT_ID),
        PublicKey(TOKEN_PROGRAM_ID),
        PublicKey(SYSVAR_CLOCK_PUBKEY),
        PublicKey(SYSVAR_INSTRUCTION_PUBKEY),
        PublicKey(KECCAK_PROGRAM),
        PublicKey(SYSVAR_RENT_PUBKEY),
        PublicKey(INCINERATOR_PUBKEY),
        PublicKey(SYS_PROGRAM_ID),
    ]

    def __init__(self):
        # Initialize user account
        self.signer = get_solana_accounts()[0]
        self._operator = self.signer.public_key()
        self._client = Client(SOLANA_URL)
        self.operator_token = get_associated_token_address(PublicKey(self._operator), ETH_TOKEN_MINT_ID)

        self.solana = SolanaInteractor(self._client)
        self.builder = NeonInstruction(self._operator)


    def unlock_accounts(self, blocked_storages):
        for storage, tx_accounts in blocked_storages.items():
            (neon_tx, blocked_accounts) = tx_accounts
            if blocked_accounts is None:
                self.error(f"Empty blocked accounts for the Neon tx {neon_tx}.")
            else:
                keys = []
                for acc in blocked_accounts:
                    is_writable = False if PublicKey(acc) in self.readonly_accs else True
                    keys.append(AccountMeta(pubkey=acc, is_signer=False, is_writable=is_writable))

                self.builder.init_eth_trx(neon_tx.tx, None, self.operator_token)
                self.builder.init_iterative(storage, None, 0)

                trx = self.builder.make_cancel_transaction(keys)

                self.debug(f"Send Cancel: {trx}")
                try:
                    cancel_result = self.solana.send_multiple_transactions(self.signer, [trx], None, None)[0]
                    self.debug(f"cancel result: {cancel_result}")
                except Exception as err:
                    err_tb = "".join(traceback.format_tb(err.__traceback__))
                    self.error('Exception on submitting transaction. ' +
                               f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')
                else:
                    self.debug(f"Canceled: {blocked_accounts}")
