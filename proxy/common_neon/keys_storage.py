import os
from typing import Optional, List

from .address import NeonAddress


class KeyStorage:
    def __init__(self):
        self._key_list = set()
        storage_path = self.storage_path()
        if not os.path.isfile(storage_path):
            return

        with open(storage_path, mode='r') as f:
            line_list = f.readlines()
            for line in line_list:
                pk_key_str = line.strip().lower()
                try:
                    pk_key_data = bytes.fromhex(pk_key_str)
                    NeonAddress.from_private_key(pk_key_data)
                    self._key_list.add(pk_key_str)
                except (Exception,):
                    pass

    @staticmethod
    def storage_path() -> os.path:
        dir_name = os.path.join(os.path.expanduser('~'), '.neon')
        if not os.path.isdir(dir_name):
            os.mkdir(dir_name)
        return os.path.join(dir_name, 'accounts.dat')

    def _save_to_file(self):
        with open(self.storage_path(), mode='w') as f:
            f.truncate()
            for pk_key_str in self._key_list:
                f.write(pk_key_str)
                f.write('\n')

    def generate_new(self) -> NeonAddress:
        new_address = NeonAddress.random()
        self._key_list.add(new_address.private_key.to_hex()[2:])
        self._save_to_file()
        return new_address

    def import_private_key(self, pk_key) -> NeonAddress:
        new_address = NeonAddress.from_private_key(pk_key)
        self._key_list.add(new_address.private_key.to_hex()[2:])
        self._save_to_file()
        return new_address

    def get_list(self) -> List[NeonAddress]:
        return [NeonAddress.from_private_key(bytes.fromhex(p)) for p in self._key_list]

    def get_key(self, address: NeonAddress) -> Optional[NeonAddress]:
        if not isinstance(address, NeonAddress):
            return None

        store_addr_list = self.get_list()
        for store_addr in store_addr_list:
            if store_addr == address:
                return NeonAddress.from_raw(store_addr, address.chain_id)
        return None
