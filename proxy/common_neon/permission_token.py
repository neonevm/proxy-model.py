import os

from typing import Union
from decimal import Decimal

import spl.token.instructions as spl_token

from ..common_neon.address import EthereumAddress, ether2program
from ..common_neon.solana_transaction import SolAccount, SolPubKey, SolLegacyTx, SolWrappedTx
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx_list_sender import SolTxListSender
from ..common_neon.config import Config


class PermissionToken:
    def __init__(self, config: Config, solana: SolInteractor, token_mint: SolPubKey):
        self.config = config
        self.solana = solana
        self.token_mint = token_mint

    def get_token_account_address(self, ether_addr: Union[str, EthereumAddress]):
        sol_addr = ether2program(ether_addr)[0]
        return spl_token.get_associated_token_address(sol_addr, self.token_mint)

    def get_balance(self, ether_addr: Union[str, EthereumAddress]):
        token_account = self.get_token_account_address(ether_addr)
        return self.solana.get_token_account_balance(token_account)

    def create_account_if_needed(self, ether_addr: Union[str, EthereumAddress], signer: SolAccount):
        token_account = self.get_token_account_address(ether_addr)
        info = self.solana.get_account_info(token_account)
        if info is not None:
            return token_account

        tx = SolLegacyTx().add(
            spl_token.create_associated_token_account(
                payer=signer.public_key(),
                owner=ether2program(ether_addr)[0],
                mint=self.token_mint
            )
        )
        tx_list = [SolWrappedTx(name='CreateAssociatedTokenAccount', tx=tx)]
        SolTxListSender(self.config, self.solana, signer, skip_preflight=True).send(tx_list)
        return token_account

    def mint_to(self, amount: int, ether_addr: Union[str, EthereumAddress],
                mint_authority_file: str, signer: SolAccount):
        token_account = self.create_account_if_needed(ether_addr, signer)
        mint_command = f'spl-token mint "{str(self.token_mint)}" {Decimal(amount) * pow(Decimal(10), -9)}'
        mint_command += f' --owner {mint_authority_file} -- "{str(token_account)}"'
        os.system(mint_command)
