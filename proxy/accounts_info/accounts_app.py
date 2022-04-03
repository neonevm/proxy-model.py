import math
import json
import sha3

from proxy.common_neon.address import EthereumAddress, accountWithSeed
from proxy.common_neon.solana_interactor import SolanaInteractor
from ..environment import PERM_ACCOUNT_LIMIT, SOLANA_URL, get_solana_accounts


class AccountsApp:
    def __init__(self):
        self._solana = SolanaInteractor(SOLANA_URL)

    def run(self) -> int:
        try:
            ret_js = self.do_work()
            print(f"{json.dumps(ret_js)}")
        except Exception as err:
            print(f'Failed to execute AccountsApp: {err}')
            return 1
        return 0

    def do_work(self):
        resource_tags = {
            0: 'TAG_EMPTY',
            1: 'TAG_ACCOUNT_V1',
            10: 'TAG_ACCOUNT',
            2: 'TAG_CONTRACT',
            3: 'TAG_STORAGE_V1',
            30: 'TAG_STORAGE',
            4: 'TAG_ERC20_ALLOWANCE',
            5: 'TAG_FINALIZED_STORAGE',
        }

        ret_js = {}
        ret_js['accounts'] = []

        operator_accounts = get_solana_accounts()
        neon_accounts = [EthereumAddress.from_private_key(operator.secret_key()) for operator in operator_accounts]

        for sol_account, neon_account in zip(operator_accounts, neon_accounts):
            acc_info_js = {}
            acc_info_js['solana_address'] = str(sol_account.public_key())
            acc_info_js['solana_balance'] = self._solana.get_sol_balance(sol_account.public_key())
            acc_info_js['neon_address'] = str(neon_account)
            neon_layout = self._solana.get_account_info_layout(neon_account)
            acc_info_js['neon_balance'] = neon_layout.balance if neon_layout else 0
            acc_info_js['neon_private'] = str(neon_account.private)

            resources = []

            for rid in range(max(PERM_ACCOUNT_LIMIT, 16)):
                aid = rid.to_bytes(math.ceil(rid.bit_length() / 8), 'big')
                seed_list = [prefix + aid for prefix in [b"storage", b"holder"]]
                for seed_base in seed_list:
                    resource_account = {}
                    seed = sha3.keccak_256(seed_base).hexdigest()[:32]
                    seed = bytes(seed, 'utf8')
                    account = accountWithSeed(sol_account.public_key(), seed)
                    account_info = self._solana.get_account_info(account)
                    resource_account['address'] = str(account)
                    if account_info:
                        resource_account['status'] = resource_tags.get(account_info.tag, 'unknown')
                    else:
                        resource_account['status'] = 'uninitialized'
                    resources.append(resource_account)

            acc_info_js['resource_keys'] = resources

            ret_js['accounts'].append(acc_info_js)

        return ret_js
