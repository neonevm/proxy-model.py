import base64
import os
import logging
from typing import List, Optional

import hvac
from hvac.api.secrets_engines.kv_v2 import DEFAULT_MOUNT_POINT

from .config import Config
from .environment_utils import SolanaCli
from .solana_tx import SolAccount


LOG = logging.getLogger(__name__)


class OpSecretMng:
    def __init__(self, config: Config):
        self._config = config

    def read_secret_list(self) -> List[bytes]:
        if self._config.hvac_url is not None:
            secret_list = self._read_secret_list_from_hvac()
        else:
            secret_list = self._read_secret_list_from_fs()

        if len(secret_list) == 0:
            LOG.warning("No secrets")
        else:
            LOG.debug(f"Got secret list of: {len(secret_list)} - keys")

        return secret_list

    def _read_secret_list_from_hvac(self) -> List[bytes]:
        LOG.debug('Read secret keys from HashiCorp Vault...')

        client = hvac.Client(url=self._config.hvac_url, token=self._config.hvac_token)
        if not client.is_authenticated():
            LOG.warning('Cannot connect to HashiCorp Vault!')
            return []

        secret_list: List[bytes] = []

        mount = self._config.hvac_mount if self._config.hvac_mount is not None else DEFAULT_MOUNT_POINT

        base_path = self._config.hvac_path
        try:
            response_list = client.secrets.kv.v2.list_secrets(path=base_path, mount_point=mount)
        except BaseException as exc:
            LOG.warning(f'Fail to read secret list from {base_path}')
            return []

        for key_name in response_list.get('data', {}).get('keys', []):
            key_path = os.path.join(base_path, key_name)
            try:
                data = client.secrets.kv.v2.read_secret(path=key_path, mount_point=mount)
                secret = data.get('data', {}).get('data', {}).get('secret_key', None)
                if secret is None:
                    LOG.warning(f'No secret_key in the path {key_path}')
                    continue

                sol_account = SolAccount.from_seed(base64.b64decode(secret))
                secret_list.append(sol_account.secret())
                LOG.debug(f'Get secret: {str(sol_account.pubkey())}')

            except (Exception, ):
                LOG.warning(f'Fail to read secret from {key_path}')

        return secret_list

    @staticmethod
    def _read_secret_file(name: str) -> Optional[SolAccount]:
        LOG.debug(f"Open a secret file: {name}")
        with open(name.strip(), mode='r') as d:
            pkey = (d.read())
            num_list = [int(v) for v in pkey.strip("[] \n").split(',') if 0 <= int(v) <= 255]
            if len(num_list) < 32:
                LOG.debug(f'Wrong content in the file {name}')
                return None
            return SolAccount.from_seed(bytes(num_list[:32]))

    def _read_secret_list_from_fs(self) -> List[bytes]:
        LOG.debug('Read secret keys from filesystem...')

        res = SolanaCli(self._config, False).call('config', 'get')
        LOG.debug(f"Read solana config with the length {len(res)}")
        substr = "Keypair Path: "
        path = ""
        for line in res.splitlines():
            if line.startswith(substr):
                path = line[len(substr):].strip()
        if path == "":
            LOG.warning("cannot get keypair path")
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
            secret_list.append(secret.secret())
            LOG.debug(f'Get secret: {str(secret.pubkey())}')

        return secret_list
