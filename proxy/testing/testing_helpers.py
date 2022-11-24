from __future__ import annotations

import os
import secrets
import signal
import requests
import solcx
from dataclasses import dataclass
from eth_account.account import LocalAccount as NeonLocalAccount, Account as NeonAccount, SignedTransaction
from web3 import Web3, eth as web3_eth
from web3.types import TxReceipt, HexBytes, Wei, TxParams
from typing import Type, Dict, Union

from proxy.common_neon.web3 import NeonWeb3

@dataclass(frozen=True)
class ContractCompiledInfo:
    contract_interface: Dict
    contract: Type[web3_eth.Contract]


@dataclass(frozen=True)
class ContractDeployedInfo:
    contract: web3_eth.Contract
    tx_hash: HexBytes
    tx_receipt: TxReceipt


@dataclass(frozen=True)
class TransactionSigned:
    tx: TxParams
    tx_signed: SignedTransaction


@dataclass(frozen=True)
class TransactionSended:
    tx: TxParams
    tx_signed: SignedTransaction
    tx_hash: HexBytes
    tx_receipt: TxReceipt


class Proxy:
    _CONTRACT_TYPE = Type[web3_eth.Contract]

    def __init__(self):
        proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
        self._web3 = NeonWeb3(Web3.HTTPProvider(proxy_url))
        self._proxy = self._web3.eth
        self._proxy.set_gas_price_strategy(self._get_gas_price)

    @staticmethod
    def _get_gas_price(w3: Web3, _: TxParams) -> Wei:
        return w3.eth.gas_price

    @staticmethod
    def request_airdrop(account: Union[NeonAccount, NeonLocalAccount, str], amount: int = 0):
        if amount == 0:
            amount = 5000

        if not isinstance(account, str):
            account = account.address

        faucet_url = os.environ.get('FAUCET_URL', 'http://faucet:3333')
        url = faucet_url + '/request_neon'
        data = f'{{"wallet": "{account}", "amount": {amount}}}'
        r = requests.post(url, data=data)
        if not r.ok:
            print()
            print('Bad response:', r)
        assert r.ok

    def _create_account(self, seed: str) -> NeonLocalAccount:
        if seed is None:
            private_key = "0x" + secrets.token_hex(32)
            return NeonAccount.from_key(private_key)
        return self._proxy.account.create(seed)

    def create_account(self, seed: str = None) -> NeonLocalAccount:
        return self._create_account(seed)

    def create_signer_account(self, seed: str = None, balance: int = 0) -> NeonLocalAccount:
        signer = self.create_account(seed)
        self.request_airdrop(signer, balance)
        return signer

    def create_default_account(self, seed: str) -> NeonLocalAccount:
        account = self.create_account(seed)
        self._proxy.default_account = account.address
        return account

    @property
    def conn(self) -> Web3.eth:
        return self._proxy

    @property
    def web3(self) -> NeonWeb3:
        return self._web3

    def sign_transaction(self, signer: NeonLocalAccount, tx: dict) -> TransactionSigned:
        if 'gas' not in tx:
            tx['gas'] = 987654321
        if 'chainId' not in tx:
            tx['chainId'] = self._proxy.chain_id
        if 'gasPrice' not in tx:
            tx['gasPrice'] = self._proxy.gas_price
        if 'nonce' not in tx:
            tx['nonce'] = self._proxy.get_transaction_count(signer.address, 'pending')
        if 'from' not in tx:
            tx['from'] = signer.address
        return TransactionSigned(
            tx=tx,
            tx_signed=self._proxy.account.sign_transaction(tx, signer.key)
        )

    def send_wait_transaction(self, tx: TransactionSigned) -> TransactionSended:
        print(f' -> {tx.tx}: {tx.tx_signed}')
        tx_hash = self._proxy.send_raw_transaction(tx.tx_signed.rawTransaction)
        tx_receipt = self._proxy.wait_for_transaction_receipt(tx_hash)
        return TransactionSended(
            tx=tx.tx,
            tx_signed=tx.tx_signed,
            tx_hash=tx_hash,
            tx_receipt=tx_receipt
        )

    def sign_send_wait_transaction(self, signer: NeonLocalAccount, tx: dict) -> TransactionSended:
        tx = self.sign_transaction(signer, tx)
        return self.send_wait_transaction(tx)

    def compile_contract(self, solidity_source_code: str) -> ContractCompiledInfo:
        """Returns tuple of """
        compile_result = solcx.compile_source(solidity_source_code)
        _, contract_interface = compile_result.popitem()
        contract = self._proxy.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        return ContractCompiledInfo(contract_interface, contract)

    def compile_and_deploy_contract(self, contract_owner: NeonLocalAccount,
                                    solidity_source_code: str,
                                    *args, **kwargs) -> ContractDeployedInfo:
        compiled_info = self.compile_contract(solidity_source_code)
        contract = compiled_info.contract
        tx = contract.constructor(*args, *kwargs).build_transaction()
        tx = self.sign_send_wait_transaction(contract_owner, tx)
        contract = self._proxy.contract(
            address=tx.tx_receipt.contractAddress,
            abi=contract.abi,
            bytecode=contract.bytecode
        )
        return ContractDeployedInfo(contract=contract, tx_hash=tx.tx_hash, tx_receipt=tx.tx_receipt)

    def compile_and_deploy_from_file(self, signer, contract_file) -> ContractDeployedInfo:
        with open(contract_file) as distributor_sol:
            source = distributor_sol.read()
        return self.compile_and_deploy_contract(signer, source)


class TestTimeoutExc(Exception):
    pass


class TestTimeout:
    def __init__(self, seconds, error_message=None):
        if error_message is None:
            error_message = 'test timed out after {}s.'.format(seconds)
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TestTimeoutExc(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.alarm(0)
