import os
import unittest
import json
from environment import NEON_PERMISSION_ALLOWANCE_TOKEN, NEON_PERMISSION_DENIAL_TOKEN
from spl.token.client import Token as SplToken
from spl.token.constants import TOKEN_PROGRAM_ID
from solana.publickey import PublicKey
from solana.account import Account as SolanaAccount
from solana.rpc.api import Client as SolanaClient
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts
from web3 import Web3
from solcx import install_solc

install_solc(version='0.7.0')
from solcx import compile_source

STORAGE_SOLIDITY_SOURCE_147 = '''
pragma solidity >=0.7.0 <0.9.0;
/**
 * @title Storage
 * @dev Store & retrieve value in a variable
 */
contract Storage {
    uint256 number;
    /**
     * @dev Store value in variable
     * @param num value to store
     */
    function store(uint256 num) public {
        number = num;
    }
    /**
     * @dev Return value
     * @return value of 'number'
     */
    function retrieve() public view returns (uint256){
        return number;
    }
}
'''

class TestWhiteLists(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.solana = SolanaClient(os.environ['SOLANA_URL'])
        cls.signer = SolanaAccount()
        cls.solana.request_airdrop(cls.signer.public_key(), 1000_000_000_000, Confirmed)
        with open("proxy/evm_loader-keypair.json") as f:
            d = json.load(f)
        cls.mint_authority = SolanaAccount(d[0:32])

        proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
        cls.proxy = Web3(Web3.HTTPProvider(proxy_url))
        cls.eth_account = cls.proxy.eth.account.create('https://github.com/neonlabsorg/proxy-model.py/issues/468')
        cls.proxy.eth.default_account = cls.eth_account.address
        cls.deploy_storage_147_solidity_contract(cls)

        cls.permission_allowance_token = None
        if isinstance(NEON_PERMISSION_ALLOWANCE_TOKEN, PublicKey):
            print(f'Permission allowance token: {NEON_PERMISSION_ALLOWANCE_TOKEN}')
            cls.permission_allowance_token = SplToken(cls.solana, 
                                                      NEON_PERMISSION_ALLOWANCE_TOKEN, 
                                                      TOKEN_PROGRAM_ID,
                                                      cls.signer)
        else:
            print('Permission allowance token is not set up')

        cls.permission_denial_token = None
        if isinstance(NEON_PERMISSION_DENIAL_TOKEN, PublicKey):
            print(f'Permission denial token: {NEON_PERMISSION_DENIAL_TOKEN}')
            cls.permission_denial_token = SplToken(cls.solana, 
                                                   NEON_PERMISSION_DENIAL_TOKEN, 
                                                   TOKEN_PROGRAM_ID,
                                                   cls.signer)
        else:
            print('Permission denial token is not set up')


    def deploy_storage_147_solidity_contract(self):
        compiled_sol = compile_source(STORAGE_SOLIDITY_SOURCE_147)
        contract_id, contract_interface = compiled_sol.popitem()
        storage = self.proxy.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        trx_deploy = self.proxy.eth.account.sign_transaction(dict(
            nonce=self.proxy.eth.get_transaction_count(self.proxy.eth.default_account),
            chainId=self.proxy.eth.chain_id,
            gas=987654321,
            gasPrice=0,
            to='',
            value=0,
            data=storage.bytecode),
            self.eth_account.key
        )
        print('trx_deploy:', trx_deploy)
        trx_deploy_hash = self.proxy.eth.send_raw_transaction(trx_deploy.rawTransaction)
        print('trx_deploy_hash:', trx_deploy_hash.hex())
        trx_deploy_receipt = self.proxy.eth.wait_for_transaction_receipt(trx_deploy_hash)
        print('trx_deploy_receipt:', trx_deploy_receipt)

        self.deploy_block_hash = trx_deploy_receipt['blockHash']
        self.deploy_block_num = trx_deploy_receipt['blockNumber']
        print('deploy_block_hash:', self.deploy_block_hash)
        print('deploy_block_num:', self.deploy_block_num)

        self.storage_contract = self.proxy.eth.contract(
            address=trx_deploy_receipt.contractAddress,
            abi=storage.abi
        )                                
    

    def mint_permission_allowance_token(self, target: PublicKey, amount: int):
        self.permission_allowance_token.mint_to(target, self.mint_authority, amount,
                                                opts=TxOpts(skip_preflight=True, skip_confirmation=False))

    def mint_permission_denial_token(self, target: PublicKey, amount: int):
        self.permission_denial_token.mint_to(target, self.mint_authority, amount,
                                             opts=TxOpts(skip_preflight=True, skip_confirmation=False))


    def test_reject_transaction_from_banned_sender(self):
        """
        Should reject transaction from sender that was banned
        https://github.com/neonlabsorg/proxy-model.py/issues/468
        """

        print("1st: try to send transaction without banning sender - transaction should complete")
        right_nonce = self.proxy.eth.get_transaction_count(self.proxy.eth.default_account)
        value_to_store = 452356
        trx_store = self.storage_contract.functions.store(value_to_store).buildTransaction({'nonce': right_nonce})
        print('trx_store:', trx_store)
        trx_store_signed = self.proxy.eth.account.sign_transaction(trx_store, self.eth_account.key)
        print('trx_store_signed:', trx_store_signed)
        trx_store_hash = self.proxy.eth.send_raw_transaction(trx_store_signed.rawTransaction)
        print('trx_store_hash:', trx_store_hash.hex())
        trx_store_receipt = self.proxy.eth.wait_for_transaction_receipt(trx_store_hash)
        print('trx_store_receipt:', trx_store_receipt)