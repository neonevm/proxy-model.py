import hvac
import os
import base64

from typing import List, Optional

from logged_groups import logged_group

from ..common_neon.config import Config
from ..common_neon.solana_tx import SolAccount
from ..common_neon.environment_utils import SolanaCli


@logged_group("neon.Decorder")
class OpSecretMng:
    def __init__(self, config: Config):
        self._config = config

    def read_secret_list(self) -> List[bytes]:
        if self._config.hvac_url is not None:
            return self._read_secret_list_from_hvac()
        return self._read_secret_list_from_fs()

    def _read_secret_list_from_hvac(self) -> List[bytes]:
        client = hvac.Client(url=self._config.hvac_url, token=self._config.hvac_token)
        if not client.is_authenticated():
            self.warning('Cannot connect to hashicorp vault!')
            return []

        secret_list: List[bytes] = []

        base_path = self._config.hvac_path
        response_list = client.secrets.kv.v2.list_secrets(path=base_path)

        for key_name in response_list.get('data', {}).get('keys', []):
            key_path = os.path.join(base_path, key_name)
            try:
                data = client.secrets.kv.v2.read_secret(key_path)
                secret = data.get('data', {}).data('data', {}).get('secret_key', None)
                if secret is None:
                    self.warning(f'No secret_key in the path {key_path}')
                    continue

                sol_account = SolAccount.from_secret_key(base64.b64decode(secret))
                secret_list.append(sol_account.secret_key)
                self.debug(f'Get secret: {str(secret.public_key)}')

            except Exception as exc:
                self.warning(f'Fail to read secret from {key_path}', exc_info=exc)

        return self._read_secret_list_from_fs()

    def _read_secret_file(self, name: str) -> Optional[SolAccount]:
        self.debug(f"Open a secret file: {name}")
        with open(name.strip(), mode='r') as d:
            pkey = (d.read())
            num_list = [int(v) for v in pkey.strip("[] \n").split(',') if 0 <= int(v) <= 255]
            if len(num_list) < 32:
                self.debug(f'Wrong content in the file {name}')
                return None
            return SolAccount.from_secret_key(bytes(num_list[:32]))

    def _read_secret_list_from_fs(self) -> List[bytes]:
        res = SolanaCli(self._config).call('config', 'get')
        self.debug(f"Got solana config: {res}")
        substr = "Keypair Path: "
        path = ""
        for line in res.splitlines():
            if line.startswith(substr):
                path = line[len(substr):].strip()
        if path == "":
            self.warning("cannot get keypair path")
            return []

        path = path.strip()
        file_name, file_ext = os.path.splitext(path)

        secret_list: List[bytes] = []

        i = 0
        while True:
            i += 1
            full_path = file_name + (str(i) if i > 1 else '') + file_ext
            if not os.path.isfile(full_path):
                break

            secret = self._read_secret_file(full_path)
            if secret is None:
                continue
            secret_list.append(secret.secret_key)
            self.debug(f'Get secret: {str(secret.public_key)}')

        if len(secret_list) == 0:
            self.warning("No secrets")

        self.debug(f"Got secret list of: {len(secret_list)} - keys")
        return secret_list

