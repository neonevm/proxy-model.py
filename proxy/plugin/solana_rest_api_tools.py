import os

import eth_utils
import math

from datetime import datetime
from solana.publickey import PublicKey
from solana.rpc.api import Client as SolanaClient
from solana.rpc.commitment import Confirmed
from logged_groups import logged_group

from ..common_neon.address import ether2program, getTokenAddr, EthereumAddress
from ..common_neon.errors import SolanaAccountNotFoundError, SolanaErrors
from ..common_neon.utils import get_from_dict, get_holder_msg
from ..common_neon.transaction_sender import NeonTxSender, NeonCreateContractTxStage, NeonCreateAccountTxStage
from ..environment import NEW_USER_AIRDROP_AMOUNT, read_elf_params, TIMEOUT_TO_RELOAD_NEON_CONFIG, EXTRA_GAS, EVM_STEPS, \
    EVM_BYTE_COST, HOLDER_MSG_SIZE, GAS_MULTIPLIER, ACCOUNT_MAX_SIZE, SPL_TOKEN_ACCOUNT_SIZE

@logged_group("neon.Proxy")
def neon_config_load(ethereum_model, *, logger):
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


@logged_group("neon.Proxy")
def get_token_balance_gwei(client: SolanaClient, pda_account: str, *, logger) -> int:
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
        logger.error(
            f"Failed to get_token_balance_gwei by neon_token_account: {neon_token_account}, response: {rpc_response}")
        raise Exception("Unexpected get_balance response")
    return int(balance)


@logged_group("neon.Proxy")
def get_token_balance_or_airdrop(client: SolanaClient, eth_account: EthereumAddress, *, logger) -> int:
    solana_account, nonce = ether2program(eth_account)
    logger.debug(f"Get balance for eth account: {eth_account} aka: {solana_account}")

    try:
        return get_token_balance_gwei(client, solana_account)
    except SolanaAccountNotFoundError:
        logger.debug(f"Account not found:  {eth_account} aka: {solana_account} - return airdrop amount")
        return NEW_USER_AIRDROP_AMOUNT * eth_utils.denoms.gwei


def is_account_exists(client: SolanaClient, eth_account: EthereumAddress) -> bool:
    pda_account, nonce = ether2program(eth_account)
    info = client.get_account_info(pda_account, commitment=Confirmed)
    value = get_from_dict(info, "result", "value")
    return value is not None


@logged_group("neon.Proxy")
def estimate_gas(tx_sender: NeonTxSender, sender,  *, logger):
    tx_sender.operator_key = PublicKey(os.urandom(32))
    tx_sender._call_emulated(sender)
    tx_sender._parse_accounts_list();

    msg = get_holder_msg(tx_sender.eth_tx)
    holder_iterations = math.ceil(len(msg)/HOLDER_MSG_SIZE)
    begin_iterations = 1

    space = 0
    for s in tx_sender._create_account_list:
        if s.NAME == NeonCreateContractTxStage.NAME:
            space += s.size + ACCOUNT_MAX_SIZE + SPL_TOKEN_ACCOUNT_SIZE
        elif s.NAME == NeonCreateAccountTxStage.NAME:
            space +=  ACCOUNT_MAX_SIZE + SPL_TOKEN_ACCOUNT_SIZE

    space += tx_sender.unpaid_space

    gas_for_trx = (tx_sender.steps_emulated + (holder_iterations + begin_iterations) * EVM_STEPS) * GAS_MULTIPLIER
    gas_for_space = space * EVM_BYTE_COST * GAS_MULTIPLIER
    gas = gas_for_trx + gas_for_space + EXTRA_GAS
    # if gas < 21000:
    #     gas = 21000

    logger.debug(f'number of holder iterations: {holder_iterations}')
    logger.debug(f'allocated space: {space}')
    logger.debug(f'gas_for_space: {gas_for_space}')
    logger.debug(f'gas_for_trx: {gas_for_trx}')
    logger.debug(f'extra_gas: {EXTRA_GAS}')
    logger.debug(f'estimated gas: {gas}')
    return gas
