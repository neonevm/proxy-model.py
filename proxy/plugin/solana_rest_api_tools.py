import logging
import random
import base64
from datetime import datetime
from eth_keys import keys as eth_keys
from solana.publickey import PublicKey
from solana.rpc.commitment import Confirmed
from proxy.environment import read_elf_params, TIMEOUT_TO_RELOAD_NEON_CONFIG, NEW_USER_AIRDROP_AMOUNT


from proxy.common_neon.transaction_sender import TransactionSender
from proxy.common_neon.solana_interactor import SolanaInteractor
from proxy.common_neon.address import ether2program, getTokenAddr, ACCOUNT_INFO_LAYOUT, AccountInfo


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class EthereumAddress:
    def __init__(self, data, private=None):
        if isinstance(data, str):
            data = bytes(bytearray.fromhex(data[2:]))
        self.data = data
        self.private = private

    @staticmethod
    def random():
        letters = '0123456789abcdef'
        data = bytearray.fromhex(''.join([random.choice(letters) for k in range(64)]))
        pk = eth_keys.PrivateKey(data)
        return EthereumAddress(pk.public_key.to_canonical_address(), pk)

    def __str__(self):
        return '0x'+self.data.hex()

    def __repr__(self):
        return self.__str__()

    def __bytes__(self): return self.data


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


def _getAccountData(client, account, expected_length, owner=None):
    info = client.get_account_info(account, commitment=Confirmed)['result']['value']
    if info is None:
        raise Exception("Can't get information about {}".format(account))

    data = base64.b64decode(info['data'][0])
    if len(data) < expected_length:
        raise Exception("Wrong data length for account data {}".format(account))
    return data


def getAccountInfo(client, eth_account: EthereumAddress):
    account_sol, nonce = ether2program(eth_account)
    info = _getAccountData(client, account_sol, ACCOUNT_INFO_LAYOUT.sizeof())
    return AccountInfo.frombytes(info)


def getTokens(client, signer, evm_loader, eth_acc, base_account):
    (account, nonce) = ether2program(bytes(eth_acc).hex(), evm_loader, base_account)
    token_account = getTokenAddr(PublicKey(account))

    balance = client.get_token_account_balance(token_account, commitment=Confirmed)
    if 'error' in balance:
        if NEW_USER_AIRDROP_AMOUNT > 0:
            return NEW_USER_AIRDROP_AMOUNT * 1_000_000_000
        else:
            logger.debug("'error' in balance:")
            return 0

    return int(balance['result']['value']['amount'])


