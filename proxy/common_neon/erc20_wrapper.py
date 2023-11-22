import json
import logging
from typing import Union, Dict, Any, Tuple, Optional

from eth_account.signers.local import LocalAccount as NeonAccount

from spl.token.client import Token

from solana.rpc.types import TxOpts
from solana.rpc.commitment import Confirmed

from solcx import install_solc, compile_source

from .solana_tx import SolAccountMeta, SolAccount, SolPubKey
from .constants import ACCOUNT_SEED_VERSION, EVM_PROGRAM_ID
from .utils.eth_proto import NeonTx
from .neon_instruction import NeonIxBuilder
from .web3 import NeonWeb3, ChecksumAddress


install_solc(version='0.7.6')

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
    neon_contract_address: ChecksumAddress
    solana_contract_address: SolPubKey
    interface: Dict
    wrapper: Dict

    def __init__(self,
                 proxy: NeonWeb3,
                 name: str, symbol: str,
                 token: Token,
                 admin: NeonAccount,
                 mint_authority: SolAccount):
        self.proxy = proxy
        self.name = name
        self.symbol = symbol
        self.token = token
        self.admin = admin
        self.mint_authority = mint_authority

    def get_auth_account_address(self, neon_account_address: str) -> SolPubKey:
        neon_account_addressbytes = bytes(12) + bytes.fromhex(neon_account_address[2:])
        neon_contract_addressbytes = bytes.fromhex(self.neon_contract_address[2:])
        return SolPubKey.find_program_address(
            [ACCOUNT_SEED_VERSION, b"AUTH", neon_contract_addressbytes, neon_account_addressbytes],
            EVM_PROGRAM_ID
        )[0]

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
        tx_constructor = erc20.constructor(*init_args).build_transaction({'nonce': nonce, 'from': self.admin.address})
        tx_deploy = self.proxy.eth.account.sign_transaction(tx_constructor, self.admin.key)
        tx_deploy_hash = self.proxy.eth.send_raw_transaction(tx_deploy.rawTransaction)
        LOG.debug(f'tx_deploy_hash: {tx_deploy_hash.hex()}')
        tx_deploy_receipt = self.proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        LOG.debug(f'tx_deploy_receipt: {tx_deploy_receipt}')
        LOG.debug(f'deploy status: {tx_deploy_receipt.status}')
        self.neon_contract_address = ChecksumAddress(tx_deploy_receipt.contractAddress)
        self.solana_contract_address = self.proxy.neon.get_neon_account(self.neon_contract_address).solanaAddress

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
        return SolPubKey.find_program_address(seeds, EVM_PROGRAM_ID)[0]

    def create_associated_token_account(self, owner: SolPubKey):
        return self.token.create_associated_token_account(owner)

    def create_claim_to_ix(self, owner: SolPubKey,
                           from_acct: SolPubKey,
                           to_acct: NeonAccount,
                           amount: int,
                           signer_acct: NeonAccount,
                           nonce: Optional[int] = None):
        erc20 = self.proxy.eth.contract(address=self.neon_contract_address, abi=self.wrapper['abi'])
        if nonce is None:
            nonce = self.proxy.eth.get_transaction_count(signer_acct.address)

        claim_tx = erc20.functions.claimTo(
            bytes(from_acct),
            to_acct.address,
            amount
        ).build_transaction(
            {'nonce': nonce, 'gasPrice': 0}
        )
        return self._create_builder(claim_tx, owner, signer_acct)

    def _create_builder(self, tx, owner: SolPubKey, signer_acct: NeonAccount):
        tx = self.proxy.eth.account.sign_transaction(tx, signer_acct.key)
        pda_acct = self.proxy.neon.get_neon_account(signer_acct.address).solanaAddress

        neon_tx = bytearray.fromhex(tx.rawTransaction.hex()[2:])
        emulating_result = self.proxy.neon.neon_emulate(neon_tx)

        neon_account_dict = dict()
        for account in emulating_result['solana_accounts']:
            key = account['pubkey']
            meta = SolAccountMeta(pubkey=SolPubKey.from_string(key), is_signer=False, is_writable=True)
            neon_account_dict[key] = meta

        neon_account_dict = list(neon_account_dict.values())

        neon = NeonIxBuilder(owner)
        neon.init_operator_neon(SolPubKey.from_string(pda_acct))
        neon.init_neon_tx(NeonTx.from_string(neon_tx))
        neon.init_neon_account_list(neon_account_dict)
        return neon

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
