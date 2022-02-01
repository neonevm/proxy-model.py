import base64
import logging
import math
import os

from datetime import datetime
from solana.account import Account as SolanaAccount
from solana.publickey import PublicKey
from solana.rpc.api import Client as SolanaClient
from solana.rpc.commitment import Confirmed

from ..common_neon.address import ether2program, getTokenAddr, EthereumAddress, AccountInfo
from ..common_neon.errors import SolanaAccountNotFoundError, SolanaErrors
from ..common_neon.layouts import ACCOUNT_INFO_LAYOUT
from ..common_neon.neon_instruction import NeonInstruction
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.transaction_sender import TransactionSender, TransactionEmulator
from ..common_neon.emulator_interactor import call_emulated
from ..common_neon.utils import get_from_dict, get_holder_msg
from ..environment import NEW_USER_AIRDROP_AMOUNT, read_elf_params, TIMEOUT_TO_RELOAD_NEON_CONFIG, EXTRA_GAS, EVM_STEPS, \
    EVM_BYTE_COST, HOLDER_MSG_SIZE, GAS_MULTIPLIER
from .eth_proto import Trx as EthTrx
from typing import Optional
from eth_keys import keys as eth_keys
from web3.auto import w3

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def neon_config_load(ethereum_model):
    try:
        ethereum_model.neon_config_dict
    except AttributeError:
        logger.debug("loading the neon config dict for the first time!")
        ethereum_model.neon_config_dict = dict()
    else:
        elapsed_time = datetime.now().timestamp() - ethereum_model.neon_config_dict['load_time']
        logger.debug('elapsed_time={} proxy_id={}'.format(elapsed_time, ethereum_model.proxy_id))
        if elapsed_time < TIMEOUT_TO_RELOAD_NEON_CONFIG:
            return

    read_elf_params(ethereum_model.neon_config_dict)
    ethereum_model.neon_config_dict['load_time'] = datetime.now().timestamp()
    # 'Neon/v0.3.0-rc0-d1e4ff618457ea9cbc82b38d2d927e8a62168bec
    ethereum_model.neon_config_dict['web3_clientVersion'] = 'Neon/v' + \
                                                            ethereum_model.neon_config_dict['NEON_PKG_VERSION'] + \
                                                            '-' \
                                                            + ethereum_model.neon_config_dict['NEON_REVISION']
    logger.debug(ethereum_model.neon_config_dict)


def call_signed(signer, client, eth_trx, steps):
    solana_interactor = SolanaInteractor(signer, client)
    trx_sender = TransactionSender(solana_interactor, eth_trx, steps)
    return trx_sender.execute()


def create_eth_account_and_airdrop(client: SolanaClient, signer: SolanaAccount, eth_account: EthereumAddress):
    trx = NeonInstruction(signer.public_key()).make_trx_with_create_and_airdrop (eth_account)
    result = SolanaInteractor(signer, client).send_transaction(trx, None, reason='create_eth_account_and_airdrop')
    error = result.get("error")
    if error is not None:
        logger.error(f"Failed to create eth_account and airdrop: {eth_account}, error occurred: {error}")
        raise Exception("Create eth_account error")


def get_token_balance_gwei(client: SolanaClient, pda_account: str) -> int:
    neon_token_account = getTokenAddr(PublicKey(pda_account))
    rpc_response = client.get_token_account_balance(neon_token_account, commitment=Confirmed)
    error = rpc_response.get('error')
    if error is not None:
        message = error.get("message")
        if message == SolanaErrors.AccountNotFound.value:
            raise SolanaAccountNotFoundError()
        logger.error(f"Failed to get_token_balance_gwei by neon_token_account: {neon_token_account}, "
                     f"got get_token_account_balance error: \"{message}\"")
        raise Exception("Getting balance error")

    balance = get_from_dict(rpc_response, "result", "value", "amount")
    if balance is None:
        logger.error(f"Failed to get_token_balance_gwei by neon_token_account: {neon_token_account}, response: {rpc_response}")
        raise Exception("Unexpected get_balance response")
    return int(balance)


def get_token_balance_or_airdrop(client: SolanaClient, signer: SolanaAccount, eth_account: EthereumAddress) -> int:
    solana_account, nonce = ether2program(eth_account)
    logger.debug(f"Get balance for eth account: {eth_account} aka: {solana_account}")

    try:
        return get_token_balance_gwei(client, solana_account)
    except SolanaAccountNotFoundError:
        logger.debug(f"Account not found:  {eth_account} aka: {solana_account} - create")
        if NEW_USER_AIRDROP_AMOUNT == 0:
            return 0

        create_eth_account_and_airdrop(client, signer, eth_account)
        return get_token_balance_gwei(client, solana_account)


def is_account_exists(client: SolanaClient, eth_account: EthereumAddress) -> bool:
    pda_account, nonce = ether2program(eth_account)
    info = client.get_account_info(pda_account, commitment=Confirmed)
    value = get_from_dict(info, "result", "value")
    return value is not None


def estimate_gas(client: SolanaClient, signer: SolanaAccount, caller: bytes, contract_id: Optional[bytes],
                  value: Optional[int], data: Optional[bytes], nonce: int, chain_id: int):

    solana_interactor = SolanaInteractor(signer, client)
    transaction_emulator = TransactionEmulator(solana_interactor)
    transaction_emulator.create_account_list_by_emulate(caller, contract_id, value, data, nonce)

    if transaction_emulator.steps_emulated is None:
        logger.error(f"Failed estimate_gas, unexpected result, by contract_id: {contract_id}, caller_eth_account: "
                     f"{caller}, data: {data}, value: {value}")
        raise Exception("Bad estimate_gas result")

    trx = {
        'to': contract_id if contract_id else "",
        'value': value if value else 0,
        'gas': 999999999,
        'gasPrice': 1_000_000_000,
        'nonce': nonce,
        'data': data.hex() if data else "",
        'chainId': chain_id
    }

    signed_trx = w3.eth.account.sign_transaction(trx, eth_keys.PrivateKey(os.urandom(32)))
    msg = get_holder_msg(EthTrx.fromString(signed_trx.rawTransaction))

    # holder account write
    holder_iterations = math.ceil(len(msg)/HOLDER_MSG_SIZE)
    begin_iterations = 1


    gas_for_space = transaction_emulator.allocated_space * EVM_BYTE_COST * GAS_MULTIPLIER
    gas_for_trx = (transaction_emulator.steps_emulated + (holder_iterations + begin_iterations) * EVM_STEPS) * GAS_MULTIPLIER
    gas = gas_for_trx + gas_for_space + EXTRA_GAS

    logger.debug("allocated space: %s", transaction_emulator.allocated_space)
    logger.debug("gas_for_space: %s", gas_for_space)
    logger.debug("gas_for_trx: %s", gas_for_trx)
    logger.debug("estimated gas: %s", gas)
    return gas
