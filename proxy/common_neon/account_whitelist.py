from datetime import datetime
from typing import Union
from logged_groups import logged_group

from ..common_neon.address import EthereumAddress
from ..common_neon.permission_token import PermissionToken
from ..common_neon.solana_transaction import SolPubKey, SolAccount
from ..common_neon.elf_params import ElfParams
from ..common_neon.config import Config
from ..common_neon.solana_interactor import SolInteractor


@logged_group("neon.AccountWhitelist")
class AccountWhitelist:
    def __init__(self, config: Config, solana: SolInteractor):
        self.solana = solana
        self.account_cache = {}
        self.permission_update_int = config.account_permission_update_int
        self.mint_authority_file = "/spl/bin/evm_loader-keypair.json"
        self.allowance_token = None
        self.denial_token = None

        allowance_token_addr = ElfParams().allowance_token_addr
        denial_token_addr = ElfParams().denial_token_addr
        if allowance_token_addr == '' and denial_token_addr == '':
            return

        if allowance_token_addr == '' or denial_token_addr == '':
            self.error(f'Wrong proxy configuration: allowance and denial tokens must both exist or absent!')
            raise Exception("NEON service is unhealthy. Try again later")

        self.allowance_token = PermissionToken(config, self.solana, SolPubKey(allowance_token_addr))
        self.denial_token = PermissionToken(config, self.solana, SolPubKey(denial_token_addr))

    def read_balance_diff(self, ether_addr: Union[str, EthereumAddress]) -> int:
        token_list = [
            self.allowance_token.get_token_account_address(ether_addr),
            self.denial_token.get_token_account_address(ether_addr)
        ]

        balance_list = self.solana.get_token_account_balance_list(token_list)
        allowance_balance = balance_list[0]
        denial_balance = balance_list[1]
        return allowance_balance - denial_balance

    def grant_permissions(self, ether_addr: Union[str, EthereumAddress], min_balance: int, signer: SolAccount):
        try:
            diff = self.read_balance_diff(ether_addr)
            if diff >= min_balance:
                self.info(f'{ether_addr} already has permission')
                return True

            to_mint = min_balance - diff
            self.allowance_token.mint_to(to_mint, ether_addr, self.mint_authority_file, signer)
            self.info(f'Permissions granted to {ether_addr}')
            return True
        except BaseException as exc:
            self.error(f'Failed to grant permissions to {ether_addr}', exc_info=exc)
            return False

    def deprive_permissions(self, ether_addr: Union[str, EthereumAddress], min_balance: int, signer: SolAccount):
        try:
            diff = self.read_balance_diff(ether_addr)
            if diff < min_balance:
                self.info(f'{ether_addr} already deprived')
                return True

            to_mint = diff - min_balance + 1
            self.denial_token.mint_to(to_mint, ether_addr, self.mint_authority_file, signer)
            self.info(f'Permissions deprived to {ether_addr}')
            return True
        except BaseException as exc:
            self.error(f'Failed to grant permissions to {ether_addr}', exc_info=exc)
            return False

    def grant_client_permissions(self, ether_addr: Union[str, EthereumAddress], signer: SolAccount):
        return self.grant_permissions(ether_addr, ElfParams().neon_minimal_client_allowance_balance, signer)

    def grant_contract_permissions(self, ether_addr: Union[str, EthereumAddress], signer: SolAccount):
        return self.grant_permissions(ether_addr, ElfParams().neon_minimal_contract_allowance_balance, signer)

    def deprive_client_permissions(self, ether_addr: Union[str, EthereumAddress], signer: SolAccount):
        return self.deprive_permissions(ether_addr, ElfParams().neon_minimal_client_allowance_balance, signer)

    def deprive_contract_permissions(self, ether_addr: Union[str, EthereumAddress], signer: SolAccount):
        return self.deprive_permissions(ether_addr, ElfParams().neon_minimal_contract_allowance_balance, signer)

    def get_current_time(self):
        return datetime.now().timestamp()

    def has_permission(self, ether_addr: Union[str, EthereumAddress], min_balance: int):
        if self.allowance_token is None and self.denial_token is None:
            return True

        cached = self.account_cache.get(ether_addr, None)
        current_time = self.get_current_time()
        if cached is not None:
            diff = current_time - cached['last_update']
            if diff < self.permission_update_int:
                return cached['diff'] >= min_balance

        try:
            diff = self.read_balance_diff(ether_addr)
            self.account_cache[ether_addr] = {
                'last_update': current_time,
                'diff': diff
            }
            return diff >= min_balance
        except BaseException as exc:
            self.error(f'Failed to read permissions for {ether_addr}', exc_info=exc)

    def has_client_permission(self, ether_addr: Union[str, EthereumAddress]):
        return self.has_permission(ether_addr, ElfParams().neon_minimal_client_allowance_balance)

    def has_contract_permission(self, ether_addr: Union[str, EthereumAddress]):
        return self.has_permission(ether_addr, ElfParams().neon_minimal_contract_allowance_balance)
