# File: test_neon_faucet.py
# Test for the faucet service.

import unittest
import os
import io
import time
import subprocess
import requests
from web3 import Web3
from solcx import install_solc
install_solc(version='0.7.6')
from solcx import compile_source
from proxy.environment import EVM_LOADER_ID, SOLANA_URL
from proxy.indexer.airdropper import run_airdropper
from solana.publickey import PublicKey
from multiprocessing import Process
from solana.rpc.api import Client as SolanaClient
from solana.account import Account as SolanaAccount
from spl.token.client import Token as SplToken
from spl.token.constants import TOKEN_PROGRAM_ID
from solana.rpc.commitment import Confirmed
from proxy.common_neon.neon_instruction import NeonInstruction
from solana.rpc.types import TxOpts
from time import sleep
import json

issue = 'https://github.com/neonlabsorg/neon-evm/issues/166'
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
admin = proxy.eth.account.create(issue + '/admin')
user = proxy.eth.account.create(issue + '/user')
airdrop_src_user = proxy.eth.account.create('airdrop_src_user')
airdrop_trg_user = proxy.eth.account.create('airdrop_trg_user')
proxy.eth.default_account = admin.address

FAUCET_RPC_PORT = 3333

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

class Test_Neon_Faucet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print('\n\n' + issue)
        cls.compile_erc20_contract(cls)
        cls.token_a = cls.deploy_erc20_token(cls, 'A')
        cls.token_b = cls.deploy_erc20_token(cls, 'B')
        cls.start_faucet(cls)
        time.sleep(1)

    def compile_erc20_contract(self):
        print('Compiling ERC20 contract...')
        compiled_contract = compile_source(ERC20_CONTRACT_SOURCE)
        contract_id, contract_interface = compiled_contract.popitem()
        self.contract = contract_interface

    def deploy_erc20_token(self, name):
        print('Deploying ERC20 token...')
        erc20 = proxy.eth.contract(abi=self.contract['abi'], bytecode=self.contract['bin'])
        nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx = {'nonce': nonce}
        tx_constructor = erc20.constructor().buildTransaction(tx)
        tx_deploy = proxy.eth.account.sign_transaction(tx_constructor, admin.key)
        tx_deploy_hash = proxy.eth.send_raw_transaction(tx_deploy.rawTransaction)
        tx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        print('Token', name, '=', tx_deploy_receipt.contractAddress)
        return tx_deploy_receipt.contractAddress

    def start_faucet(self):
        os.environ['FAUCET_RPC_PORT'] = str(FAUCET_RPC_PORT)
        os.environ['FAUCET_RPC_ALLOWED_ORIGINS'] = 'http://localhost'
        os.environ['FAUCET_WEB3_ENABLE'] = 'true'
        os.environ['WEB3_RPC_URL'] = proxy_url
        os.environ['WEB3_PRIVATE_KEY'] = admin.key.hex()
        os.environ['NEON_ERC20_TOKENS'] = self.token_a + ',' + self.token_b
        os.environ['NEON_ERC20_MAX_AMOUNT'] = '1000'
        os.environ['FAUCET_SOLANA_ENABLE'] = 'true'
        os.environ['SOLANA_URL'] = os.environ.get('SOLANA_URL', 'http://solana:8899')
        os.environ['EVM_LOADER'] = os.environ.get('EVM_LOADER', '53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io')
        os.environ['NEON_TOKEN_MINT'] = 'HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU'
        os.environ['NEON_TOKEN_MINT_DECIMALS'] = '9'
        os.environ['NEON_OPERATOR_KEYFILE'] = '/root/.config/solana/id.json'
        os.environ['NEON_ETH_MAX_AMOUNT'] = '10'
        self.faucet = subprocess.Popen(['faucet', 'run', '--workers', '1'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def create_token_mint(self):
        self.solana_client = SolanaClient(SOLANA_URL)

        # with open("/root/.config/solana/id.json") as f:
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

    def create_token_accounts(self):
        contract_address_bytes = bytes.fromhex(self.token_a[2:])
        contract_address_solana = PublicKey.find_program_address([b"\1", contract_address_bytes], EVM_LOADER_ID)[0]

        admin_address_bytes = bytes.fromhex(admin.address[2:])
        admin_address_solana = PublicKey.find_program_address([b"\1", admin_address_bytes], EVM_LOADER_ID)[0]

        admin_token_seeds = [ b"\1", b"ERC20Balance", bytes(self.token.pubkey), contract_address_bytes, admin_address_bytes ]
        admin_token_key = PublicKey.find_program_address(admin_token_seeds, EVM_LOADER_ID)[0]
        admin_token_info = { "key": admin_token_key, "owner": admin_address_solana, "contract": contract_address_solana, "mint": self.token.pubkey }

        instr = NeonInstruction(self.solana_account.public_key()).createERC20TokenAccountTrx(admin_token_info)
        self.solana_client.send_transaction(instr, self.solana_account, opts=TxOpts(skip_preflight=True, skip_confirmation=False))
        self.token.mint_to(admin_token_key, self.solana_account, 10_000_000_000_000, opts=TxOpts(skip_preflight=True, skip_confirmation=False))

    # @unittest.skip("a.i.")
    def test_neon_faucet_01_eth_token(self):
        print()
        # First request - trigger creation of the account without real transfer
        url = f'http://localhost:{FAUCET_RPC_PORT}/request_eth_token'
        data = '{"wallet": "' + user.address + '", "amount": 0}'
        r = requests.post(url, data=data)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)
        # Second request - actual test
        balance_before = proxy.eth.get_balance(user.address)
        print('NEO balance before:', balance_before)
        url = f'http://localhost:{FAUCET_RPC_PORT}/request_eth_token'
        data = '{"wallet": "' + user.address + '", "amount": 1}'
        r = requests.post(url, data=data)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)
        # Check
        balance_after = proxy.eth.get_balance(user.address)
        print('NEO balance after:', balance_after)
        print('NEO balance difference:', balance_after - balance_before)
        self.assertEqual(balance_after - balance_before, 1000000000000000000)

    # @unittest.skip("a.i.")
    def test_neon_faucet_02_erc20_tokens(self):
        print()
        a_before = self.get_token_balance(self.token_a, user.address)
        b_before = self.get_token_balance(self.token_b, user.address)
        print('token A balance before:', a_before)
        print('token B balance before:', b_before)
        url = f'http://localhost:{FAUCET_RPC_PORT}/request_erc20_tokens'
        data = '{"wallet": "' + user.address + '", "amount": 1}'
        r = requests.post(url, data=data)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)
        a_after = self.get_token_balance(self.token_a, user.address)
        b_after = self.get_token_balance(self.token_b, user.address)
        print('token A balance after:', a_after)
        print('token B balance after:', b_after)
        self.assertEqual(a_after - a_before, 1000000000000000000)
        self.assertEqual(b_after - b_before, 1000000000000000000)

    def get_token_balance(self, token_address, address):
        erc20 = proxy.eth.contract(address=token_address, abi=self.contract['abi'])
        return erc20.functions.balanceOf(address).call()

    def stop_faucet(self):
        url = f'http://localhost:{FAUCET_RPC_PORT}/request_stop'
        data = '{"delay": 1000}' # 1 second
        r = requests.post(url, data=data)
        if not r.ok:
            self.faucet.terminate()
        with io.TextIOWrapper(self.faucet.stdout, encoding="utf-8") as out:
            for line in out:
                print(line.strip())

    def test_airdropper(self):
        token_a_address_bytes = bytes.fromhex(self.token_a[2:])
        token_a_address_solana = PublicKey.find_program_address([b"\1", token_a_address_bytes], EVM_LOADER_ID)[0]
        wrapper_whitelist = [str(token_a_address_solana)]
        print(f'Wrapper whitelist {wrapper_whitelist}')
        log_level = 'INFO'
        airdropper = Process(target=run_airdropper,
                             args=(
                                 SOLANA_URL,
                                 EVM_LOADER_ID,
                                 f'http://localhost:{FAUCET_RPC_PORT}',
                                 wrapper_whitelist,
                                 log_level
                             ))
        airdropper.start()


        airdropper.terminate()
        airdropper.join()

    @classmethod
    def tearDownClass(cls):
        cls.stop_faucet(cls)

if __name__ == '__main__':
    unittest.main()
