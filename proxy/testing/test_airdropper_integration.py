from unittest import TestCase

from solcx import compile_source
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

PROXY_URL = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
FAUCET_RPC_PORT = 3333
NAME = 'NEON'
SYMBOL = 'NEO'

proxy = Web3(Web3.HTTPProvider(PROXY_URL))
admin = proxy.eth.account.create('neonlabsorg/proxy-model.py/issues/344')
account_from = proxy.eth.account.create('neonlabsorg/proxy-model.py/issues/344/account_from')
account_to = proxy.eth.account.create('neonlabsorg/proxy-model.py/issues/344/account_to')

ERC20_CONTRACT_SOURCE = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0;
// ----------------------------------------------------------------------------
// Safe maths
// ----------------------------------------------------------------------------
contract SafeMath {
    function safeAdd(uint a, uint b) public pure returns (uint c) {
        c = a + b;
        require(c >= a);
    }
    function safeSub(uint a, uint b) public pure returns (uint c) {
        require(b <= a);
        c = a - b;
    }
}
// ----------------------------------------------------------------------------
// ERC Token Standard #20 Interface
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
// ----------------------------------------------------------------------------
abstract contract ERC20Interface {
    function totalSupply() virtual public view returns (uint);
    function balanceOf(address tokenOwner) virtual public view returns (uint balance);
    function allowance(address tokenOwner, address spender) virtual public view returns (uint remaining);
    function transfer(address to, uint tokens) virtual public returns (bool success);
    function approve(address spender, uint tokens) virtual public returns (bool success);
    function transferFrom(address from, address to, uint tokens) virtual public returns (bool success);
    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}
// ----------------------------------------------------------------------------
// ERC20 Token, with the addition of symbol, name and decimals
// assisted token transfers
// ----------------------------------------------------------------------------
contract TestToken is ERC20Interface, SafeMath {
    string public symbol;
    string public  name;
    uint8 public decimals;
    uint public _totalSupply;
    mapping(address => uint) balances;
    mapping(address => mapping(address => uint)) allowed;
    // ------------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------------
    constructor() {
        symbol = "TST";
        name = "TestToken";
        decimals = 18;
        _totalSupply = 100000000000000000000000000000000000000000;
        balances[msg.sender] = _totalSupply;
        emit Transfer(address(0), msg.sender, _totalSupply);
    }
    // ------------------------------------------------------------------------
    // Total supply
    // ------------------------------------------------------------------------
    function totalSupply() public override view returns (uint) {
        return _totalSupply - balances[address(0)];
    }
    // ------------------------------------------------------------------------
    // Get the token balance for account tokenOwner
    // ------------------------------------------------------------------------
    function balanceOf(address tokenOwner) public override view returns (uint balance) {
        return balances[tokenOwner];
    }
    // ------------------------------------------------------------------------
    // Transfer the balance from token owner's account to receiver account
    // - Owner's account must have sufficient balance to transfer
    // - 0 value transfers are allowed
    // ------------------------------------------------------------------------
    function transfer(address receiver, uint tokens) public override returns (bool success) {
        balances[msg.sender] = safeSub(balances[msg.sender], tokens);
        balances[receiver] = safeAdd(balances[receiver], tokens);
        emit Transfer(msg.sender, receiver, tokens);
        return true;
    }
    // ------------------------------------------------------------------------
    // Token owner can approve for spender to transferFrom(...) tokens
    // from the token owner's account
    //
    // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
    // recommends that there are no checks for the approval double-spend attack
    // as this should be implemented in user interfaces
    // ------------------------------------------------------------------------
    function approve(address spender, uint tokens) public override returns (bool success) {
        allowed[msg.sender][spender] = tokens;
        emit Approval(msg.sender, spender, tokens);
        return true;
    }
    // ------------------------------------------------------------------------
    // Transfer tokens from sender account to receiver account
    //
    // The calling account must already have sufficient tokens approve(...)-d
    // for spending from sender account and
    // - From account must have sufficient balance to transfer
    // - Spender must have sufficient allowance to transfer
    // - 0 value transfers are allowed
    // ------------------------------------------------------------------------
    function transferFrom(address sender, address receiver, uint tokens) public override returns (bool success) {
        balances[sender] = safeSub(balances[sender], tokens);
        allowed[sender][msg.sender] = safeSub(allowed[sender][msg.sender], tokens);
        balances[receiver] = safeAdd(balances[receiver], tokens);
        emit Transfer(sender, receiver, tokens);
        return true;
    }
    // ------------------------------------------------------------------------
    // Returns the amount of tokens approved by the owner that can be
    // transferred to the spender's account
    // ------------------------------------------------------------------------
    function allowance(address tokenOwner, address spender) public override view returns (uint remaining) {
        return allowed[tokenOwner][spender];
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
        faucet_env['EVM_LOADER'] = EVM_LOADER_ID
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

    def setUpClass(cls) -> None:
        cls.create_token_mint()
        cls.deploy_erc20_wrapper_contract()
        cls.start_faucet()

    def tearDownClass(cls) -> None:
        cls.stop_faucet()

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
        return PublicKey.find_program_address(account_token_seeds, EVM_LOADER_ID)[0]

    def create_eth_account_instr(self, eth_account):
        account_address_bytes = bytes.fromhex(eth_account.address[2:])
        account_address_solana, nonce = PublicKey.find_program_address([b"\1", account_address_bytes], EVM_LOADER_ID)[0]
        neon_token_account = get_associated_token_address(account_address_solana, ETH_TOKEN_MINT_ID)

        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=create_account_layout(0, 0, bytes(eth_account.address), nonce),
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

    def create_token_account_instr(self, eth_account):
        contract_address_bytes = bytes.fromhex(self.contract_address[2:])
        contract_address_solana = PublicKey.find_program_address([b"\1", contract_address_bytes], EVM_LOADER_ID)[0]
        account_address_bytes = bytes.fromhex(eth_account.address[2:])
        account_address_solana = PublicKey.find_program_address([b"\1", account_address_bytes], EVM_LOADER_ID)[0]
        account_token_key = self.get_token_account_address(eth_account)
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=bytes.fromhex('0F'),
            keys=[
                AccountMeta(pubkey=self.solana_account.public_key(), is_signer=True, is_writable=True),
                AccountMeta(pubkey=account_token_key, is_signer=False, is_writable=True),
                AccountMeta(pubkey=account_address_solana, is_signer=False, is_writable=True),
                AccountMeta(pubkey=contract_address_solana, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.token.pubkey, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
            ]
        )


    def transfer_token_instr(self, from_eth_account, to_eth_account, amount):
        transfer_params = TransferParams(self.token.pubkey,
                                         self.get_token_account_address(from_eth_account),
                                         self.get_token_account_address(to_eth_account),
                                         self.get_token_account_address(from_eth_account),
                                         amount)
        return transfer(transfer_params)


    def create_token_account(self, eth_account):
        trx = Transaction()
        trx.add(self.create_token_account_instr(eth_account))
        self.solana_client.send_transaction(trx, self.solana_account,
                                            opts=TxOpts(skip_preflight=True,
                                                        skip_confirmation=False))


    def get_token_balance(self, token_address, address):
        erc20 = proxy.eth.contract(address=token_address, abi=self.contract['abi'])
        return erc20.functions.balanceOf(address).call()


    def mint_to_account(self, eth_account, amount):
        self.token.mint_to(self.get_token_account_address(eth_account),
                           self.solana_account, amount,
                           opts=TxOpts(skip_preflight=True, skip_confirmation=False))

    def test_success_airdrop_simple_case(self):
        from_eth_account = self.create_new_eth_account()
        to_eth_account = self.create_new_eth_account()
        transfer_amount = 100

        self.create_token_account(from_eth_account)
        self.mint_to_account(from_eth_account, 1000)

        trx = Transaction()
        trx.add(self.create_eth_account_instr(to_eth_account))
        trx.add(self.create_token_account_instr(to_eth_account))
        trx.add(self.transfer_token_instr(from_eth_account, to_eth_account, transfer_amount))
        self.solana_client.send_transaction(trx, self.solana_account,
                                            opts=TxOpts(skip_preflight=True,
                                                        skip_confirmation=False))

