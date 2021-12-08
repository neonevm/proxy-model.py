from unittest import TestCase

from solcx import install_solc
from solana.rpc.api import Client as SolanaClient
from solana.account import Account as SolanaAccount
from spl.token.client import Token as SplToken
from spl.token.instructions import get_associated_token_address, transfer, TransferParams
from proxy.environment import SOLANA_URL, EVM_LOADER_ID, ETH_TOKEN_MINT_ID
from solana.system_program import SYS_PROGRAM_ID
from solana.sysvar import SYSVAR_RENT_PUBKEY
from spl.token.constants import TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID
from solana.rpc.commitment import Confirmed
from solana.publickey import PublicKey
from solana.rpc.types import TxOpts
from solana.transaction import TransactionInstruction, Transaction, AccountMeta
from proxy.common_neon.neon_instruction import NeonInstruction, create_account_layout
from time import sleep
from web3 import Web3
from random import randint
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
admin = proxy.eth.account.create('neonlabsorg/proxy-model.py/issues/344/admin')
dest = proxy.eth.account.create('neonlabsorg/proxy-model.py/issues/344/dest')
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

class TestAirdropperIntegration(TestCase):
    def create_token_mint(self):
        self.solana_client = SolanaClient(SOLANA_URL)

        with open("proxy/operator-keypair.json") as f:
            d = json.load(f)
        self.solana_account = SolanaAccount(d[0:32])
        self.solana_client.request_airdrop(self.solana_account.public_key(), 1000_000_000_000, Confirmed)

        while True:
            balance = self.solana_client.get_balance(self.solana_account.public_key(), Confirmed)["result"]["value"]
            if balance > 0:
                break
            sleep(1)
        print('create_token_mint mint, SolanaAccount: ', self.solana_account.public_key())

        self.token = SplToken.create_mint(
            self.solana_client,
            self.solana_account,
            self.solana_account.public_key(),
            9,
            TOKEN_PROGRAM_ID,
        )

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

    def create_token_accounts(self):
        contract_address_bytes = bytes.fromhex(self.contract_address[2:])
        contract_address_solana = PublicKey.find_program_address([b"\1", contract_address_bytes], EVM_LOADER_ID)[0]

        admin_address_bytes = bytes.fromhex(admin.address[2:])
        admin_address_solana = PublicKey.find_program_address([b"\1", admin_address_bytes], EVM_LOADER_ID)[0]

        admin_token_seeds = [b"\1", b"ERC20Balance", bytes(self.token.pubkey), contract_address_bytes,
                             admin_address_bytes]
        admin_token_key = PublicKey.find_program_address(admin_token_seeds, EVM_LOADER_ID)[0]
        admin_token_info = {"key": admin_token_key, "owner": admin_address_solana, "contract": contract_address_solana,
                            "mint": self.token.pubkey}

        instr = NeonInstruction(self.solana_account.public_key()).createERC20TokenAccountTrx(admin_token_info)
        self.solana_client.send_transaction(instr, self.solana_account,
                                            opts=TxOpts(skip_preflight=True, skip_confirmation=False))
        self.token.mint_to(admin_token_key, self.solana_account, 10_000_000_000_000,
                           opts=TxOpts(skip_preflight=True, skip_confirmation=False))

    def start_faucet(self):
        faucet_env = os.environ.copy()
        faucet_env['FAUCET_RPC_PORT'] = str(FAUCET_RPC_PORT)
        faucet_env['FAUCET_RPC_ALLOWED_ORIGINS'] = 'http://localhost'
        faucet_env['FAUCET_WEB3_ENABLE'] = 'true'
        faucet_env['WEB3_RPC_URL'] = PROXY_URL
        faucet_env['WEB3_PRIVATE_KEY'] = admin.key.hex()
        faucet_env['NEON_ERC20_TOKENS'] = self.contract_address
        faucet_env['NEON_ERC20_MAX_AMOUNT'] = '1000'
        faucet_env['FAUCET_SOLANA_ENABLE'] = 'true'
        faucet_env['SOLANA_URL'] = SOLANA_URL
        faucet_env['EVM_LOADER'] = str(EVM_LOADER_ID)
        faucet_env['NEON_TOKEN_MINT'] = str(ETH_TOKEN_MINT_ID)
        faucet_env['NEON_TOKEN_MINT_DECIMALS'] = '9'
        faucet_env['NEON_OPERATOR_KEYFILE'] = '/root/.config/solana/id.json'
        faucet_env['NEON_ETH_MAX_AMOUNT'] = '10'
        self.faucet = subprocess.Popen(['faucet', 'run', '--workers', '1'],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT,
                                       env=faucet_env)

    def stop_faucet(self):
        url = f'http://localhost:{FAUCET_RPC_PORT}/request_stop'
        data = '{"delay": 1000}' # 1 second
        r = requests.post(url, data=data)
        if not r.ok:
            self.faucet.terminate()
        with io.TextIOWrapper(self.faucet.stdout, encoding="utf-8") as out:
            for line in out:
                print(line.strip())

    @classmethod
    def setUpClass(cls) -> None:
        cls.create_token_mint(cls)
        cls.deploy_erc20_wrapper_contract(cls)
        cls.create_token_accounts(cls)
        cls.start_faucet(cls)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stop_faucet(cls)

    def create_new_eth_account(self):
        seed = ''
        for i in range(0, 40):
            seed += str(randint(0, 9))
        return proxy.eth.account.create(seed)

    def get_token_account_address(self, eth_account):
        contract_address_bytes = bytes.fromhex(self.contract_address[2:])
        account_address_bytes = bytes.fromhex(eth_account.address[2:])
        account_token_seeds = [b"\1", b"ERC20Balance",
                               bytes(self.token.pubkey),
                               contract_address_bytes,
                               account_address_bytes]
        token_account = PublicKey.find_program_address(account_token_seeds, EVM_LOADER_ID)[0]
        print(f"\n\n\nTOKEN ACCOUNT: {token_account}")
        return token_account

    def create_eth_account_instr(self, eth_account):
        account_address_bytes = bytes.fromhex(eth_account.address[2:])
        account_address_solana, nonce = PublicKey.find_program_address([b"\1", account_address_bytes], EVM_LOADER_ID)
        neon_token_account = get_associated_token_address(account_address_solana, ETH_TOKEN_MINT_ID)

        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=create_account_layout(0, 0, account_address_bytes, nonce),
            keys=[
                AccountMeta(pubkey=self.solana_account.public_key(), is_signer=True, is_writable=True),
                AccountMeta(pubkey=account_address_solana, is_signer=False, is_writable=True),
                AccountMeta(pubkey=neon_token_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=ETH_TOKEN_MINT_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=ASSOCIATED_TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
            ])

    def get_neon_account_address(self, eth_address: str):
        address_bytes = bytes.fromhex(eth_address[2:])
        neon_acc = PublicKey.find_program_address([b"\1", address_bytes], EVM_LOADER_ID)[0]
        print(f"\n\n\n\nNEON ACCOUNT: {neon_acc}")
        return neon_acc

    def create_token_account_instr(self, eth_account):
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=bytes.fromhex('0F'),
            keys=[
                AccountMeta(pubkey=self.solana_account.public_key(), is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.get_token_account_address(eth_account), is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.get_neon_account_address(eth_account.address), is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.get_neon_account_address(self.contract_address), is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.token.pubkey, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
            ]
        )


    def transfer_token_instr(self, from_eth_account, to_eth_account, amount):
        transfer_params = TransferParams(program_id=self.token.pubkey,
                                         source=self.get_token_account_address(from_eth_account),
                                         dest=self.get_token_account_address(to_eth_account),
                                         owner=self.solana_account.public_key(),
                                         amount=amount)
        return transfer(transfer_params)


    def create_token_account(self, eth_account):
        trx = Transaction()
        trx.add(self.create_token_account_instr(eth_account))
        self.solana_client.send_transaction(trx, self.solana_account,
                                            opts=TxOpts(skip_preflight=True,
                                                        skip_confirmation=False))


    def get_token_balance(self, token_address, address):
        erc20 = proxy.eth.contract(address=token_address, abi=self.interface['abi'])
        return erc20.functions.balanceOf(address).call()


    def mint_to_account(self, eth_account, amount):
        self.token.mint_to(self.get_token_account_address(eth_account),
                           self.solana_account, amount,
                           opts=TxOpts(skip_preflight=True, skip_confirmation=False))

    def test_success_airdrop_simple_case(self):
        contract_address_bytes = bytes.fromhex(self.contract_address[2:])
        contract_address_solana = PublicKey.find_program_address([b"\1", contract_address_bytes], EVM_LOADER_ID)[0]



        dest_address_bytes = bytes.fromhex(dest.address[2:])
        dest_address_solana, nonce = PublicKey.find_program_address([b"\1", dest_address_bytes], EVM_LOADER_ID)
        dest_token_seeds = [b"\1", b"ERC20Balance", bytes(self.token.pubkey), contract_address_bytes,
                             dest_address_bytes]
        dest_token_key = PublicKey.find_program_address(dest_token_seeds, EVM_LOADER_ID)[0]
        dest_token_info = {"key": dest_token_key, "owner": dest_address_solana, "contract": contract_address_solana,
                            "mint": self.token.pubkey}


        admin_address_bytes = bytes.fromhex(admin.address[2:])
        admin_token_seeds = [b"\1", b"ERC20Balance", bytes(self.token.pubkey), contract_address_bytes,
                             admin_address_bytes]
        admin_token_key = PublicKey.find_program_address(admin_token_seeds, EVM_LOADER_ID)[0]



        neon_token_account = get_associated_token_address(dest_address_solana, ETH_TOKEN_MINT_ID)


        trx = Transaction()
        trx.add(TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=create_account_layout(0, 0, dest_address_bytes, nonce),
            keys=[
                AccountMeta(pubkey=self.solana_account.public_key(), is_signer=True, is_writable=True),
                AccountMeta(pubkey=dest_address_solana, is_signer=False, is_writable=True),
                AccountMeta(pubkey=neon_token_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=ETH_TOKEN_MINT_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=ASSOCIATED_TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
            ]))

        trx.add(TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=bytes.fromhex('0F'),
            keys=[
                AccountMeta(pubkey=self.solana_account.public_key(), is_signer=True, is_writable=True),
                AccountMeta(pubkey=dest_token_info["key"], is_signer=False, is_writable=True),
                AccountMeta(pubkey=dest_token_info["owner"], is_signer=False, is_writable=True),
                AccountMeta(pubkey=dest_token_info["contract"], is_signer=False, is_writable=True),
                AccountMeta(pubkey=dest_token_info["mint"], is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
            ]
        ))

        transfer_params = TransferParams(program_id=self.token.pubkey,
                                         source=admin_token_key,
                                         dest=dest_token_key,
                                         owner=self.solana_account.public_key(),
                                         amount=100000)
        trx.add(transfer(transfer_params))


        self.solana_client.send_transaction(trx, self.solana_account,
                                            opts=TxOpts(skip_preflight=True,
                                                        skip_confirmation=False))
