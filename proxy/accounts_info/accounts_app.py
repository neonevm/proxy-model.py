import math
import json
import sha3

from proxy.common_neon.address import EthereumAddress, accountWithSeed
from ..environment import PERM_ACCOUNT_LIMIT, get_solana_accounts


class AccountsApp:
    def run(self) -> int:
        try:
            ret_js = self.do_work()
            print(f"{json.dumps(ret_js)}")
        except Exception as err:
            print(f'Failed to execute AccountsApp: {err}')
            return 1
        return 0

    def do_work(self):
        ret_js = {}
        ret_js['accounts'] = []

        operator_accounts = get_solana_accounts()
        neon_accounts = [EthereumAddress.from_private_key(operator.secret_key()) for operator in operator_accounts]

        for sol_account, neon_account in zip(operator_accounts, neon_accounts):
            acc_info_js = {}
            acc_info_js['solana_address'] = str(sol_account.public_key())
            acc_info_js['neon_address'] = str(neon_account)
            acc_info_js['neon_private'] = str(neon_account.private)

            resources = []

            for rid in range(max(PERM_ACCOUNT_LIMIT, 16)):
                aid = rid.to_bytes(math.ceil(rid.bit_length() / 8), 'big')
                seed_list = [prefix + aid for prefix in [b"storage", b"holder"]]
                for seed_base in seed_list:
                    seed = sha3.keccak_256(seed_base).hexdigest()[:32]
                    seed = bytes(seed, 'utf8')
                    resource_account = accountWithSeed(sol_account.public_key(), seed)
                    resources.append(str(resource_account))

            acc_info_js['resource_keys'] = resources

            ret_js['accounts'].append(acc_info_js)

        return ret_js
