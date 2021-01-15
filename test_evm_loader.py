# -*- coding: utf-8 -*-
# requires:
# pip3 install -r requirements.txt
# pip3 install solana
from proxy.plugin.wrapper import EvmLoaderProgram
from solana.rpc.api import Client
from solana.account import Account
from solana.publickey import PublicKey
from solana.transaction import AccountMeta, TransactionInstruction, Transaction
import unittest
import time
import os
import secrets

solana_url = os.environ.get("SOLANA_URL")
if solana_url is None:
    print("Please set SOLANA_URL environment")
    exit(1)
http_client = Client(solana_url)

evm_loader = os.environ.get("EVM_LOADER")  #"CLBfz3DZK4VBYAu6pCgDrQkNwLsQphT9tg41h6TQZAh3"

if evm_loader is None:
    print("Please set EVM_LOADER environment")
    exit(1)

system_program_key = os.environ.get("SYSTEM_PROGRAM_KEY")  #"CLBfz3DZK4VBYAu6pCgDrQkNwLsQphT9tg41h6TQZAh3"

if system_program_key is None:
    print("Please set SYSTEM_PROGRAM_KEY environment")
    exit(1)

def confirm_transaction(client, tx_sig):
    """Confirm a transaction."""
    TIMEOUT = 30  # 30 seconds  pylint: disable=invalid-name
    elapsed_time = 0
    while elapsed_time < TIMEOUT:
        sleep_time = 3
        if not elapsed_time:
            sleep_time = 7
            time.sleep(sleep_time)
        else:
            time.sleep(sleep_time)
        resp = client.get_confirmed_transaction(tx_sig)
        if resp["result"]:
#            print('Confirmed transaction:', resp)
            break
        elapsed_time += sleep_time
    if not resp["result"]:
        raise RuntimeError("could not confirm transaction: ", tx_sig)
    return resp

class EvmLoaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.acc = Account(b'\xdc~\x1c\xc0\x1a\x97\x80\xc2\xcd\xdfn\xdb\x05.\xf8\x90N\xde\xf5\x042\xe2\xd8\x10xO%/\xe7\x89\xc0<')
        print('Account:', cls.acc.public_key(), bytes(cls.acc.public_key()).hex())
        print('Private:', cls.acc.secret_key())
        balance = http_client.get_balance(cls.acc.public_key())['result']['value']
        if balance == 0:
            tx = http_client.request_airdrop(cls.acc.public_key(), 10*10**9)
            confirm_transaction(http_client, tx['result'])
            balance = http_client.get_balance(cls.acc.public_key())['result']['value']
        print('Balance:', balance)

        # caller created with "50b41b481f04ac2949c9cc372b8f502aa35bddd1" ethereum address
        cls.caller = PublicKey("A8semLLUsg5ZbhACjD2Vdvn8gpDZV1Z2dPwoid9YUr4S")

    def test_createAccount(self):
        program = EvmLoaderProgram()
        addr = secrets.token_hex(20)
        print('Creating account: ', addr)
        # lamports, space, ether, signer_key, program_key, system_program_key
        trx = Transaction().add(
            program.createAccount(1000, 1000, addr, system_program_key, system_program_key, system_program_key)
        )
        result = http_client.send_transaction(trx, self.acc)

    def test_call(self):
        program = EvmLoaderProgram()
        addr = secrets.token_hex(20)
        print('Creating account: ', addr)
        # lamports, space, ether, signer_key, program_key, system_program_key
        trx = Transaction().add(
            program.createAccount(1000, 1000, addr, system_program_key, system_program_key, system_program_key)
        )
        result = http_client.send_transaction(trx, self.acc)
        trx = Transaction().add(
            program.call('0xf8b018850bdfd63e00830186a094b80102fd2d3d1be86823dd36f9c783ad0ee7d89880b844a9059cbb000000000000000000000000cac68f98c1893531df666f2d58243b27dd351a8800000000000000000000000000000000000000000000000000000000000000208602e92be91e86a05ed7d0093a991563153f59c785e989a466e5e83bddebd9c710362f5ee23f7dbaa023a641d304039f349546089bc0cb2a5b35e45619fd97661bd151183cb47f1a0a', addr, self.acc) # TODO signer in future
        )
        result = http_client.send_transaction(trx, self.acc)

if __name__ == '__main__':
    unittest.main()
