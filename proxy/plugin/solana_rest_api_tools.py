import base64
import eth_utils

from datetime import datetime
from solana.publickey import PublicKey
from solana.rpc.api import Client as SolanaClient
from solana.rpc.commitment import Confirmed
from logged_groups import logged_group

from ..common_neon.address import ether2program, EthereumAddress
from ..common_neon.emulator_interactor import call_emulated
from ..common_neon.utils import get_from_dict
from ..environment import read_elf_params, TIMEOUT_TO_RELOAD_NEON_CONFIG, EXTRA_GAS


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


def is_account_exists(client: SolanaClient, eth_account: EthereumAddress) -> bool:
    pda_account, nonce = ether2program(eth_account)
    info = client.get_account_info(pda_account, commitment=Confirmed)
    value = get_from_dict(info, "result", "value")
    return value is not None


@logged_group("neon.Proxy")
def estimate_gas(contract_id: str, caller_eth_account: EthereumAddress, data: str = None, value: str = None, *, logger):
    result = call_emulated(contract_id, str(caller_eth_account), data, value)
    used_gas = result.get("used_gas")
    if used_gas is None:
        logger.error(f"Failed estimate_gas, unexpected result, by contract_id: {contract_id}, caller_eth_account: "
                     f"{caller_eth_account}, data: {data}, value: {value}, emulation result: {result}")
        raise Exception("Bad estimate_gas result")
    return used_gas + EXTRA_GAS
