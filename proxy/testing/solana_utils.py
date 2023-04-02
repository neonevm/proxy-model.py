import json
import os
import subprocess
from typing import Optional

from solders.keypair import Keypair


solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
path_to_solana = 'solana'


class SolanaCli:
    def __init__(self):
        pass

    def call(self, arguments):
        cmd = '{} --url {} {}'.format(path_to_solana, solana_url, arguments)
        try:
            return subprocess.check_output(cmd, shell=True, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            import sys
            print("ERR: solana error {}".format(err))
            raise


class RandomAccount:
    def __init__(self, path=None):
        if path is None:
            self.make_random_path()
            print("New keypair file: {}".format(self.path))
            self.generate_key()
        else:
            self.path = path
        self.acc: Optional[Keypair] = None
        self.retrieve_keys()
        print('New Public key:', self.acc.pubkey())
        print('Private:', self.acc.secret())

    def make_random_path(self):
        self.path = os.urandom(5).hex() + ".json"

    def generate_key(self):
        cmd_generate = 'solana-keygen new --no-passphrase --outfile {}'.format(self.path)
        try:
            return subprocess.check_output(cmd_generate, shell=True, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            import sys
            print("ERR: solana error {}".format(err))
            raise

    def retrieve_keys(self):
        with open(self.path) as f:
            d = json.load(f)
            self.acc = Keypair.from_seed(d[0:32])

    def get_path(self):
        return self.path

    def get_acc(self):
        return self.acc


class WalletAccount(RandomAccount):
    def __init__(self, path):
        self.path = path
        self.retrieve_keys()
        print('Wallet public key:', self.acc.pubkey())


def wallet_path():
    res = SolanaCli().call("config get")
    substr = "Keypair Path: "
    for line in res.splitlines():
        if line.startswith(substr):
            return line[len(substr):].strip()
    raise Exception("cannot get keypair path")
