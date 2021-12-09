from unittest import TestCase

from solcx import install_solc
from solana.rpc.api import Client as SolanaClient
from solana.account import Account as SolanaAccount
from spl.token.client import Token as SplToken
from spl.token.instructions import get_associated_token_address
from proxy.environment import SOLANA_URL, EVM_LOADER_ID, ETH_TOKEN_MINT_ID
from solana.system_program import SYS_PROGRAM_ID
from solana.sysvar import SYSVAR_RENT_PUBKEY
from spl.token.constants import TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID
from solana.rpc.commitment import Confirmed
from solana.publickey import PublicKey
from solana.rpc.types import TxOpts
from solana.transaction import TransactionInstruction, Transaction, AccountMeta
from proxy.common_neon.neon_instruction import create_account_layout
from time import sleep
from web3 import Web3
from proxy.indexer.airdropper import run_airdropper
from multiprocessing import Process
import struct
import os
import json
import subprocess
import requests
import io

install_solc(version='0.7.6')
from solcx import compile_source

EVM_LOADER_ID = PublicKey(EVM_LOADER_ID)
PROXY_URL = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
FAUCET_RPC_PORT = 3333
NAME = 'TestToken'
SYMBOL = 'TST'

proxy = Web3(Web3.HTTPProvider(PROXY_URL))
admin = proxy.eth.account.create('neonlabsorg/proxy-model.py/issues/344/admin7')
dest = proxy.eth.account.create('neonlabsorg/proxy-model.py/issues/344/dest7')
proxy.eth.default_account = admin.address

# Standard interface of ERC20 contract to generate ABI for wrapper
ERC20_INTERFACE_SOURCE = '''
pragma solidity >=0.7.0;

interface IERC20 {
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);


    function approveSolana(bytes32 spender, uint64 value) external returns (bool);
    event ApprovalSolana(address indexed owner, bytes32 indexed spender, uint64 value);
}
'''

# Copy of contract: https://github.com/neonlabsorg/neon-evm/blob/develop/evm_loader/SPL_ERC20_Wrapper.sol
ERC20_CONTRACT_SOURCE = '''
// SPDX-License-Identifier: MIT

pragma solidity >=0.5.12;


interface IERC20 {
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);


    function approveSolana(bytes32 spender, uint64 value) external returns (bool);
    event ApprovalSolana(address indexed owner, bytes32 indexed spender, uint64 value);
}



/*abstract*/ contract NeonERC20Wrapper /*is IERC20*/ {
    address constant NeonERC20 = 0xff00000000000000000000000000000000000001;

    string public name;
    string public symbol;
    bytes32 public tokenMint;

    constructor(
        string memory _name,
        string memory _symbol,
        bytes32 _tokenMint
    ) {
        name = _name;
        symbol = _symbol;
        tokenMint = _tokenMint;
    }

    fallback() external {
        bytes memory call_data = abi.encodePacked(tokenMint, msg.data);
        (bool success, bytes memory result) = NeonERC20.delegatecall(call_data);

        require(success, string(result));

        assembly {
            return(add(result, 0x20), mload(result))
        }
    }
}
'''

# Helper function calculating solana address and nonce from given NEON(Ethereum) address
def get_evm_loader_account_address(eth_address: str):
    eth_addressbytes = bytes.fromhex(eth_address[2:])
    return PublicKey.find_program_address([b"\1", eth_addressbytes], EVM_LOADER_ID)

# Helper function calculating ERC20 wallet solana address
def get_erc20_token_wallet_address(eth_address: str,
                                   eth_contract_address: str,
                                   mint_pubkey: PublicKey):
    eth_contract_address_bytes = bytes.fromhex(eth_contract_address[2:])
    eth_address_bytes = bytes.fromhex(eth_address[2:])
    seeds = [b"\1", b"ERC20Balance", bytes(mint_pubkey), eth_contract_address_bytes, eth_address_bytes]
    return PublicKey.find_program_address(seeds, EVM_LOADER_ID)[0]

class TestAirdropperIntegration(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.create_token_mint(cls)
        cls.deploy_erc20_wrapper_contract(cls)
        cls.acc_num = 0


    def create_token_mint(self):
        self.solana_client = SolanaClient(SOLANA_URL)

        with open("proxy/operator-keypair.json") as f:
            d = json.load(f)
        self.mint_authority = SolanaAccount(d[0:32])
        self.solana_client.request_airdrop(self.mint_authority.public_key(), 1000_000_000_000, Confirmed)

        while True:
            balance = self.solana_client.get_balance(self.mint_authority.public_key(), Confirmed)["result"]["value"]
            if balance > 0:
                break
            sleep(1)
        print('create_token_mint mint, SolanaAccount: ', self.mint_authority.public_key())

        self.token = SplToken.create_mint(
            self.solana_client,
            self.mint_authority,
            self.mint_authority.public_key(),
            9,
            TOKEN_PROGRAM_ID,
        )
        sleep(20)


    def deploy_erc20_wrapper_contract(self):
        compiled_interface = compile_source(ERC20_INTERFACE_SOURCE)
        interface_id, interface = compiled_interface.popitem()
        self.interface = interface

        compiled_wrapper = compile_source(ERC20_CONTRACT_SOURCE)
        wrapper_id, wrapper_interface = compiled_wrapper.popitem()
        self.wrapper = wrapper_interface

        erc20 = proxy.eth.contract(abi=self.wrapper['abi'], bytecode=wrapper_interface['bin'])
        nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx = {'nonce': nonce}
        tx_constructor = erc20.constructor(NAME, SYMBOL, bytes(self.token.pubkey)).buildTransaction(tx)
        tx_deploy = proxy.eth.account.sign_transaction(tx_constructor, admin.key)
        tx_deploy_hash = proxy.eth.send_raw_transaction(tx_deploy.rawTransaction)
        print('tx_deploy_hash:', tx_deploy_hash.hex())
        tx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        print('tx_deploy_receipt:', tx_deploy_receipt)
        print('deploy status:', tx_deploy_receipt.status)
        self.contract_address = tx_deploy_receipt.contractAddress


    def get_token_balance(self, token_address, address):
        erc20 = proxy.eth.contract(address=token_address, abi=self.interface['abi'])
        return erc20.functions.balanceOf(address).call()


    def create_account_instruction(self, eth_address: str, payer: PublicKey):
        dest_address_solana, nonce = get_evm_loader_account_address(eth_address)
        neon_token_account = get_associated_token_address(dest_address_solana, ETH_TOKEN_MINT_ID)
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=create_account_layout(0, 0, bytes.fromhex(eth_address[2:]), nonce),
            keys=[
                AccountMeta(pubkey=payer, is_signer=True, is_writable=True),
                AccountMeta(pubkey=dest_address_solana, is_signer=False, is_writable=True),
                AccountMeta(pubkey=neon_token_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=ETH_TOKEN_MINT_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=ASSOCIATED_TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
            ])

    def create_erc20_token_account_instruction(self,
                                               eth_address,
                                               eth_contract_address: str,
                                               token_mint: PublicKey,
                                               payer: PublicKey):
        dest_address_solana, nonce = get_evm_loader_account_address(eth_address)
        contract_address_solana = get_evm_loader_account_address(eth_contract_address)[0]
        dest_token_wallet = get_erc20_token_wallet_address(eth_address, eth_contract_address, token_mint)
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=bytes.fromhex('0F'),
            keys=[
                AccountMeta(pubkey=payer, is_signer=True, is_writable=True),
                AccountMeta(pubkey=dest_token_wallet, is_signer=False, is_writable=True),
                AccountMeta(pubkey=dest_address_solana, is_signer=False, is_writable=True),
                AccountMeta(pubkey=contract_address_solana, is_signer=False, is_writable=True),
                AccountMeta(pubkey=token_mint, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
            ]
        )

    def create_input_liquidity_instruction(self,
                                           sol_from_address: PublicKey,
                                           eth_to_address: str,
                                           amount: int,
                                           eth_contract_address: str,
                                           token_mint: PublicKey,
                                           payer: PublicKey):
        dest_token_wallet = get_erc20_token_wallet_address(eth_to_address, eth_contract_address, token_mint)
        return TransactionInstruction(
            program_id=TOKEN_PROGRAM_ID,
            data=b'\3' + struct.pack('<Q', amount),
            keys=[
                AccountMeta(pubkey=sol_from_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=dest_token_wallet, is_signer=False, is_writable=True),
                AccountMeta(pubkey=payer, is_signer=True, is_writable=False)
            ]
        )

    def create_sol_account(self):
        account = SolanaAccount()
        print(f"New solana account created: {account.public_key().to_base58()}. Airdropping...")
        self.solana_client.request_airdrop(account.public_key(), 1000_000_000_000, Confirmed)
        return account

    def create_token_account(self, owner: PublicKey, token: SplToken, mint_aithority: PublicKey):
        print(f'Creating new token account. Token {token.pubkey}. Account owner {owner} ')
        new_token_account = token.create_associated_token_account(owner)
        print(f'New token account created: {new_token_account.to_base58()}')
        self.token.mint_to(new_token_account,
                           mint_aithority,
                           10_000_000_000_000,
                           opts=TxOpts(skip_preflight=True))
        return new_token_account

    def create_eth_account(self):
        self.acc_num += 1
        account = proxy.eth.account.create(f'neonlabsorg/proxy-model.py/issues/344/eth_account{self.acc_num}')
        print(f"NEON account created: {account.address}")
        return account

    def test_success_airdrop_simple_case(self):
        from_owner = self.create_sol_account()
        from_token = self.create_token_account(from_owner.public_key(), self.token, self.mint_authority)
        to_eth_account = self.create_eth_account()

        self.assertEqual(self.get_token_balance(self.contract_address, to_eth_account.address), 0)

        trx = Transaction()
        trx.add(self.create_account_instruction(to_eth_account.address, from_owner.public_key()))
        trx.add(self.create_erc20_token_account_instruction(to_eth_account.address,
                                                            self.contract_address,
                                                            self.token.pubkey,
                                                            from_owner.public_key()))
        trx.add(self.create_input_liquidity_instruction(from_token,
                                                        to_eth_account.address, 123456,
                                                        self.contract_address,
                                                        self.token.pubkey,
                                                        from_owner.public_key()))

        resp = self.solana_client.send_transaction(trx, from_owner,
                                                   opts=TxOpts(skip_preflight=True,
                                                               skip_confirmation=False))

        self.assertEqual(self.get_token_balance(self.contract_address, to_eth_account.address), 123456)
        sleep(10)
        eth_balance = proxy.eth.get_balance(to_eth_account.address)
        print("NEON balance is: ", eth_balance)
        self.assertTrue(eth_balance > 0 and eth_balance < 10 * pow(10, 18)) # 10 NEON is a max airdrop amount
