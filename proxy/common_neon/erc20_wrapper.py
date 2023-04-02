import json
import struct
import logging
from typing import Union, Dict, Any, Tuple

from eth_account.signers.local import LocalAccount as NeonAccount

from spl.token.client import Token
from spl.token.constants import TOKEN_PROGRAM_ID

from solana.rpc.types import TxOpts
from solana.rpc.commitment import Confirmed

from solcx import install_solc

from ..common_neon.solana_tx import SolTxIx, SolAccountMeta, SolAccount, SolPubKey
from ..common_neon.address import NeonAddress, neon_2program
from ..common_neon.constants import ACCOUNT_SEED_VERSION
from ..common_neon.eth_proto import NeonTx
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.web3 import NeonWeb3, ChecksumAddress

install_solc(version='0.7.6')
from solcx import compile_source


LOG = logging.getLogger(__name__)


# Standard interface of ERC20 contract to generate ABI for wrapper
ERC20FORSPL_INTERFACE_SOURCE = '''
pragma solidity >=0.7.0;

interface IERC20ForSpl {

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    event ApprovalSolana(address indexed owner, bytes32 indexed spender, uint64 amount);
    event TransferSolana(address indexed from, bytes32 indexed to, uint64 amount);

    function name() external  view returns (string memory);
    function symbol() external view returns (string memory);
    function tokenMint() external view returns (bytes32);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function burn(uint256 amount) external returns (bool);
    function burnFrom(address from, uint256 amount) external returns (bool);
    function approveSolana(bytes32 spender, uint64 amount) external returns (bool);
    function transferSolana(bytes32 to, uint64 amount) external returns (bool);
    function claim(bytes32 from, uint64 amount) external returns (bool);
    function claimTo(bytes32 from, address to, uint64 amount) external returns (bool);
}

'''


RPCResponse = Dict[str, Any]


class ERC20Wrapper:
    proxy: NeonWeb3
    name: str
    symbol: str
    token: Token
    admin: NeonAccount
    mint_authority: SolAccount
    evm_loader_id: SolPubKey
    neon_contract_address: ChecksumAddress
    solana_contract_address: SolPubKey
    interface: Dict
    wrapper: Dict

    def __init__(self, proxy: NeonWeb3,
                 name: str, symbol: str,
                 token: Token,
                 admin: NeonAccount,
                 mint_authority: SolAccount,
                 evm_loader_id: SolPubKey):
        self.proxy = proxy
        self.name = name
        self.symbol = symbol
        self.token = token
        self.admin = admin
        self.mint_authority = mint_authority
        self.evm_loader_id = evm_loader_id

    def get_auth_account_address(self, neon_account_address: str) -> SolPubKey:
        neon_account_addressbytes = bytes(12) + bytes.fromhex(neon_account_address[2:])
        neon_contract_addressbytes = bytes.fromhex(self.neon_contract_address[2:])
        return SolPubKey.find_program_address(
            [ACCOUNT_SEED_VERSION, b"AUTH", neon_contract_addressbytes, neon_account_addressbytes],
            self.evm_loader_id)[0]

    def _deploy_wrapper(self, contract: str, init_args: Tuple):
        compiled_interface = compile_source(ERC20FORSPL_INTERFACE_SOURCE)
        interface_id, interface = compiled_interface.popitem()
        self.interface = interface

        with open('contracts/erc20_for_spl.sol', 'r') as file:
            source = file.read()

        compiled_wrapper = compile_source(source, base_path="contracts", output_values=["abi", "bin"])
        wrapper_interface = compiled_wrapper[f"<stdin>:{contract}"]
        self.wrapper = wrapper_interface

        erc20 = self.proxy.eth.contract(abi=self.wrapper['abi'], bytecode=wrapper_interface['bin'])
        nonce = self.proxy.eth.get_transaction_count(self.admin.address)
        tx = {'nonce': nonce, 'from': self.admin.address}
        tx_constructor = erc20.constructor(*init_args).build_transaction(tx)
        tx_deploy = self.proxy.eth.account.sign_transaction(tx_constructor, self.admin.key)
        tx_deploy_hash = self.proxy.eth.send_raw_transaction(tx_deploy.rawTransaction)
        LOG.debug(f'tx_deploy_hash: {tx_deploy_hash.hex()}')
        tx_deploy_receipt = self.proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        LOG.debug(f'tx_deploy_receipt: {tx_deploy_receipt}')
        LOG.debug(f'deploy status: {tx_deploy_receipt.status}')
        self.neon_contract_address = ChecksumAddress(tx_deploy_receipt.contractAddress)
        self.solana_contract_address, _ = neon_2program(self.neon_contract_address)

        self.erc20 = self.proxy.eth.contract(address=self.neon_contract_address, abi=self.wrapper['abi'])

    def deploy_wrapper(self):
        self._deploy_wrapper("ERC20ForSpl", (bytes(self.token.pubkey),))

    def deploy_mintable_wrapper(self, name: str, symbol: str, decimals: int, mint_auth: str):
        neon_mint_auth = bytes.fromhex(mint_auth[2:])
        self._deploy_wrapper("ERC20ForSplMintable", (name, symbol, decimals, bytes(neon_mint_auth),))

    def get_neon_erc20_account_address(self, neon_account_address: str):
        neon_contract_address_bytes = bytes.fromhex(self.neon_contract_address[2:])
        neon_account_address_bytes = bytes.fromhex(neon_account_address[2:])
        seeds = [
            ACCOUNT_SEED_VERSION,
            b"ERC20Balance",
            bytes(self.token.pubkey),
            neon_contract_address_bytes,
            neon_account_address_bytes,
        ]
        return SolPubKey.find_program_address(seeds, self.evm_loader_id)[0]

    def create_associated_token_account(self, owner: SolPubKey):
        return self.token.create_associated_token_account(owner)

    def create_claim_instruction(self, owner: SolPubKey, from_acc: SolPubKey, to_acc: NeonAccount, amount: int):
        erc20 = self.proxy.eth.contract(address=self.neon_contract_address, abi=self.wrapper['abi'])
        nonce = self.proxy.eth.get_transaction_count(to_acc.address)
        claim_tx = erc20.functions.claim(bytes(from_acc), amount).build_transaction({'nonce': nonce, 'gasPrice': 0})
        return self._create_builder(claim_tx, owner, to_acc)

    def create_claim_to_instruction(self, owner: SolPubKey,
                                    from_acc: SolPubKey,
                                    to_acc: NeonAccount,
                                    amount: int,
                                    signer_acc: NeonAccount):
        erc20 = self.proxy.eth.contract(address=self.neon_contract_address, abi=self.wrapper['abi'])
        nonce = self.proxy.eth.get_transaction_count(signer_acc.address)
        claim_tx = erc20.functions.claimTo(bytes(from_acc), to_acc.address, amount).build_transaction(
            {'nonce': nonce, 'gasPrice': 0}
        )
        return self._create_builder(claim_tx, owner, signer_acc)

    def _create_builder(self, claim_tx, owner: SolPubKey, signer_acc: NeonAccount):
        claim_tx = self.proxy.eth.account.sign_transaction(claim_tx, signer_acc.key)

        neon_tx = bytearray.fromhex(claim_tx.rawTransaction.hex()[2:])
        emulating_result = self.proxy.neon.emulate(neon_tx)

        neon_account_dict = dict()
        for account in emulating_result['accounts']:
            key = account['account']
            meta = SolAccountMeta(pubkey=SolPubKey.from_string(key), is_signer=False, is_writable=True)
            neon_account_dict[key] = meta

        for account in emulating_result['solana_accounts']:
            key = account['pubkey']
            meta = SolAccountMeta(pubkey=SolPubKey.from_string(key), is_signer=False, is_writable=True)
            neon_account_dict[key] = meta

        neon_account_dict = list(neon_account_dict.values())

        neon = NeonIxBuilder(owner)
        neon.init_operator_neon(NeonAddress(signer_acc.address))
        neon.init_neon_tx(NeonTx.from_string(neon_tx))
        neon.init_neon_account_list(neon_account_dict)
        return neon

    def create_input_liquidity_instruction(self, payer: SolPubKey,
                                           from_address: SolPubKey,
                                           to_address: str,
                                           amount: int):
        to_address = self.get_neon_erc20_account_address(to_address)
        return SolTxIx(
            program_id=TOKEN_PROGRAM_ID,
            data=b'\3' + struct.pack('<Q', amount),
            accounts=[
                SolAccountMeta(pubkey=from_address, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=to_address, is_signer=False, is_writable=True),
                SolAccountMeta(pubkey=payer, is_signer=True, is_writable=False)
            ]
        )

    def mint_to(self, destination: Union[SolPubKey, str], amount: int) -> RPCResponse:
        """
        Method mints given amount of tokens to a given address - either in NEON or Solana format
        NOTE: destination account must be previously created
        """
        if isinstance(destination, str):
            destination = self.get_neon_erc20_account_address(destination)
        json_str = self.token.mint_to(
            destination, self.mint_authority, amount,
            opts=TxOpts(skip_preflight=True, skip_confirmation=False)
        ).to_json()
        return json.loads(json_str)

    def erc20_interface(self):
        return self.proxy.eth.contract(address=self.neon_contract_address, abi=self.interface['abi'])

    def get_balance(self, address: Union[SolPubKey, str]) -> int:
        if isinstance(address, SolPubKey):
            return int(self.token.get_balance(address, Confirmed).value.amount)

        erc20 = self.proxy.eth.contract(address=self.neon_contract_address, abi=self.interface['abi'])
        return erc20.functions.balanceOf(address).call()
