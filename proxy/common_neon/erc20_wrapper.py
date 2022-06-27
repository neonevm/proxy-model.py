from solcx import install_solc
from web3 import Web3
from spl.token.client import Token
from spl.token.constants import TOKEN_PROGRAM_ID
from eth_account.signers.local import LocalAccount as NeonAccount
from solana.rpc.api import Account as SolanaAccount
from solana.publickey import PublicKey
from solana.transaction import AccountMeta, TransactionInstruction
from solana.system_program import SYS_PROGRAM_ID
from solana.sysvar import SYSVAR_RENT_PUBKEY
from solana.rpc.types import TxOpts, RPCResponse, Commitment
import spl.token.instructions as spl_token
from typing import Union, Dict
import struct
from logged_groups import logged_group
from .compute_budget import TransactionWithComputeBudget

install_solc(version='0.7.6')
from solcx import compile_source

# Standard interface of ERC20 contract to generate ABI for wrapper
# Standard interface of ERC20 contract to generate ABI for wrapper
ERC20_INTERFACE_SOURCE = '''
pragma solidity >= 0.7.0;
pragma abicoder v2;

interface SPLToken {

    enum AccountState {
        Uninitialized,
        Initialized,
        Frozen
    }

    struct Account {
        bytes32 mint;
        bytes32 owner;
        uint64 amount;
        bytes32 delegate;
        uint64 delegated_amount;
        bytes32 close_authority;
        AccountState state;
    }

    struct Mint {
        uint64 supply;
        uint8 decimals;
        bool isInitialized;
        bytes32 freezeAuthority;
        bytes32 mintAuthority;
    }

    function findAccount(bytes32 salt) external pure returns(bytes32);

    function exists(bytes32 account) external view returns(bool);
    function getAccount(bytes32 account) external view returns(Account memory);
    function getMint(bytes32 account) external view returns(Mint memory);

    function initializeMint(bytes32 salt, uint8 decimals) external returns(bytes32);
    function initializeMint(bytes32 salt, uint8 decimals, bytes32 mint_authority, bytes32 freeze_authority) external returns(bytes32);

    function initializeAccount(bytes32 salt, bytes32 mint) external returns(bytes32);
    function initializeAccount(bytes32 salt, bytes32 mint, bytes32 owner) external returns(bytes32);

    function closeAccount(bytes32 account) external;

    function mintTo(bytes32 account, uint64 amount) external;
    function burn(bytes32 account, uint64 amount) external;

    function approve(bytes32 source, bytes32 target, uint64 amount) external;
    function revoke(bytes32 source) external;

    function transfer(bytes32 source, bytes32 target, uint64 amount) external;

    function freeze(bytes32 account) external;
    function thaw(bytes32 account) external;
}
'''

@logged_group("neon.Proxy")
class ERC20Wrapper:
    proxy: Web3
    name: str
    symbol: str
    token: Token
    admin: NeonAccount
    mint_authority: SolanaAccount
    evm_loader_id: PublicKey
    neon_contract_address: str
    solana_contract_address: PublicKey
    interface: Dict
    wrapper: Dict

    def __init__(self, proxy: Web3,
                 name: str, symbol: str,
                 token: Token,
                 admin: NeonAccount,
                 mint_authority: SolanaAccount,
                 evm_loader_id: PublicKey):
        self.proxy = proxy
        self.name = name
        self.symbol = symbol
        self.token = token
        self.admin = admin
        self.mint_authority = mint_authority
        self.evm_loader_id = evm_loader_id

    def get_neon_account_address(self, neon_account_address: str) -> PublicKey:
        neon_account_addressbytes = bytes.fromhex(neon_account_address[2:])
        return PublicKey.find_program_address([b"\1", neon_account_addressbytes], self.evm_loader_id)[0]

    def deploy_wrapper(self):
        compiled_interface = compile_source(ERC20_INTERFACE_SOURCE)
        interface_id, interface = compiled_interface.popitem()
        self.interface = interface

        with open('/opt/contracts/erc20_for_spl.sol', 'r') as file:
            source = file.read()
        compiled_wrapper = compile_source(source)
        wrapper_interface = compiled_wrapper["<stdin>:ERC20ForSpl"]
        self.wrapper = wrapper_interface

        erc20 = self.proxy.eth.contract(abi=self.wrapper['abi'], bytecode=wrapper_interface['bin'])
        nonce = self.proxy.eth.get_transaction_count(self.proxy.eth.default_account)
        tx = {'nonce': nonce}
        tx_constructor = erc20.constructor(self.name, self.symbol, bytes(self.token.pubkey)).buildTransaction(tx)
        tx_deploy = self.proxy.eth.account.sign_transaction(tx_constructor, self.admin.key)
        tx_deploy_hash = self.proxy.eth.send_raw_transaction(tx_deploy.rawTransaction)
        self.debug(f'tx_deploy_hash: {tx_deploy_hash.hex()}')
        tx_deploy_receipt = self.proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        self.debug(f'tx_deploy_receipt: {tx_deploy_receipt}')
        self.debug(f'deploy status: {tx_deploy_receipt.status}')
        self.neon_contract_address = tx_deploy_receipt.contractAddress
        self.solana_contract_address = self.get_neon_account_address(self.neon_contract_address)

    def get_neon_erc20_account_address(self, neon_account_address: str):
        neon_contract_address_bytes = bytes.fromhex(self.neon_contract_address[2:])
        neon_account_address_bytes = bytes.fromhex(neon_account_address[2:])
        seeds = [b"\1", b"ERC20Balance",
                 bytes(self.token.pubkey),
                 neon_contract_address_bytes,
                 neon_account_address_bytes]
        return PublicKey.find_program_address(seeds, self.evm_loader_id)[0]

    def create_associated_token_account(self, owner: PublicKey, payer: SolanaAccount):
        # Construct transaction
        # This part of code is based on original implementation of Token.create_associated_token_account
        # except that skip_preflight is set to True
        tx = TransactionWithComputeBudget()
        create_ix = spl_token.create_associated_token_account(
            payer=payer.public_key(), owner=owner, mint=self.token.pubkey
        )
        tx.add(create_ix)
        self.token._conn.send_transaction(tx, payer, opts=TxOpts(skip_preflight = True, skip_confirmation=False))
        return create_ix.keys[1].pubkey

    def create_neon_erc20_account_instruction(self, payer: PublicKey, eth_address: str):
        return TransactionInstruction(
            program_id=self.evm_loader_id,
            data=bytes.fromhex('0F'),
            keys=[
                AccountMeta(pubkey=payer, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.get_neon_erc20_account_address(eth_address), is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.get_neon_account_address(eth_address), is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.solana_contract_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.token.pubkey, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
            ]
        )

    def create_input_liquidity_instruction(self, payer: PublicKey, from_address: PublicKey, to_address: str, amount: int):
        return TransactionInstruction(
            program_id=TOKEN_PROGRAM_ID,
            data=b'\3' + struct.pack('<Q', amount),
            keys=[
                AccountMeta(pubkey=from_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.get_neon_erc20_account_address(to_address), is_signer=False, is_writable=True),
                AccountMeta(pubkey=payer, is_signer=True, is_writable=False)
            ]
        )

    def mint_to(self, destination: Union[PublicKey, str], amount: int) -> RPCResponse:
        """
        Method mints given amount of tokens to a given address - either in NEON or Solana format
        NOTE: destination account must be previously created
        """
        if isinstance(destination, str):
            destination = self.get_neon_erc20_account_address(destination)
        return self.token.mint_to(destination, self.mint_authority, amount,
                                  opts=TxOpts(skip_preflight=True, skip_confirmation=False))

    def erc20_interface(self):
        return self.proxy.eth.contract(address=self.neon_contract_address, abi=self.interface['abi'])

    def get_balance(self, address: Union[PublicKey, str]) -> int:
        if isinstance(address, PublicKey):
            return int(self.token.get_balance(address, Commitment('confirmed'))['result']['value']['amount'])

        erc20 = self.proxy.eth.contract(address=self.neon_contract_address, abi=self.interface['abi'])
        return erc20.functions.balanceOf(address).call()
