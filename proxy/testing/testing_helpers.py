import os
import solcx
from eth_account.account import LocalAccount
from web3 import Web3, eth as web3_eth
import eth_utils


def compile_contract(solidity_source_code: str):
    proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
    web3 = Web3(Web3.HTTPProvider(proxy_url))

    compile_result = solcx.compile_source(solidity_source_code)
    contract_id, contract_interface = compile_result.popitem()
    contract = web3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
    return contract


def compile_and_deploy_contract(contract_owner: LocalAccount, solidity_source_code: str) -> web3_eth.Contract:
    proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
    web3 = Web3(Web3.HTTPProvider(proxy_url))

    contract = compile_contract(solidity_source_code)
    nonce = web3.eth.get_transaction_count(contract_owner.address)
    chain_id = web3.eth.chain_id
    minimal_gas_price = int(os.environ.get("MINIMAL_GAS_PRICE", 1)) * eth_utils.denoms.gwei
    trx_signed = web3.eth.account.sign_transaction(
        dict(nonce=nonce, chainId=chain_id, gas=987654321, gasPrice=minimal_gas_price, to='', value=0, data=contract.bytecode),
        contract_owner.key)
    trx_hash = web3.eth.send_raw_transaction(trx_signed.rawTransaction)
    trx_receipt = web3.eth.wait_for_transaction_receipt(trx_hash)
    contract = web3.eth.contract(address=trx_receipt.contractAddress, abi=contract.abi)
    return contract
