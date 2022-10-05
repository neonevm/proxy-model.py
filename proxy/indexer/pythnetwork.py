import struct

from decimal import Decimal
from logged_groups import logged_group
from typing import List, Union, Dict, Any, Optional

from ..common_neon.solana_transaction import SolPubKey
from ..common_neon.constants import SYS_PROGRAM_ID
from ..common_neon.solana_interactor import SolInteractor


def read_str(pos, data):
    length = data[pos]
    start = pos + 1
    stop = pos + 1 + length
    return data[start:stop], stop


def read_keyvalue(pos, data):
    key, pos = read_str(pos, data)
    value, pos = read_str(pos, data)
    return key, value, pos


def read_dict(data):
    pos = 0
    result = {}
    while pos < len(data):
        key, value, pos = read_keyvalue(pos, data)
        if len(key) == 0 or len(value) == 0:
            break
        result[key.decode('utf-8')] = value.decode('utf-8')
    return result


def unpack(layout_descriptor, raw_data, field_name, index=0):
    if raw_data is None:
        raise Exception(f"Field '{field_name}': raw_data is None")

    field = layout_descriptor.get(field_name, None)
    if field is None:
        raise Exception(f'Unknown field name: {field_name}')

    length = field['len']
    start_idx = field['pos'] + index * length
    stop_idx = start_idx + length
    if start_idx >= len(raw_data) or stop_idx > len(raw_data):
        raise Exception(f"""Field '{field_name}': Index overflow:
len(raw_data) = {len(raw_data)}, start_idx = {start_idx}, stop_idx = {stop_idx}""")

    if field['format'] == 'acc':  # special case for Solana account address
        return SolPubKey(raw_data[start_idx:stop_idx])
    elif field['format'] == 'dict':  # special case for attribute mapping
        return read_dict(raw_data[start_idx:stop_idx])
    return struct.unpack(field['format'], raw_data[start_idx:stop_idx])[0]


@logged_group("neon.Airdropper")
class PythNetworkClient:
    PYTH_MAGIC = 0xa1b2c3d4
    PROD_ACCT_SIZE = 512
    PROD_HDR_SIZE = 48
    PROD_ATTR_SIZE = PROD_ACCT_SIZE - PROD_HDR_SIZE
    SUPPORTED_VERSIONS = [2]

    base_account_layout = {
        'magic': {'pos': 0, 'len': 4, 'format': '<I'},
        'ver': {'pos': 4, 'len': 4, 'format': '<I'}
    }

    mapping_account_layout = {
        'num_products': {'pos': 16, 'len': 4, 'format': '<I'},
        'next': {'pos': 24, 'len': 32, 'format': 'acc'},
        'product': {'pos': 56, 'len': 32, 'format': 'acc'}
    }

    product_account_layout = {
        'magic': {'pos': 0, 'len': 4, 'format': '<I'},
        'price_acc': {'pos': 16, 'len': 32, 'format': 'acc'},
        'attrs': {'pos': 48, 'len': PROD_ATTR_SIZE, 'format': 'dict'}
    }

    price_account_layout = {
        'expo': {'pos': 20, 'len': 4, 'format': '<i'},
        'valid_slot': {'pos': 40, 'len': 8, 'format': '<Q'},
        'agg.price': {'pos': 208, 'len': 8, 'format': '<q'},
        'agg.conf': {'pos': 216, 'len': 8, 'format': '<Q'},
        'agg.status': {'pos': 224, 'len': 4, 'format': '<I'},
    }

    def __init__(self, solana: SolInteractor):
        self.solana = solana
        self.price_accounts: Dict[str, SolPubKey] = {}

    def parse_pyth_account_data(self, acct_addr, acct_info_value):
        # it is possible when calling to getMultipleAccounts (if some accounts are absent in blockchain)
        if acct_info_value is None:
            return None

        data = acct_info_value.data
        magic = unpack(self.base_account_layout, data, 'magic')
        if magic != self.PYTH_MAGIC:
            raise RuntimeError(f'Wrong magic {magic} in account {acct_addr}')

        version = unpack(self.base_account_layout, data, 'ver')
        if version not in self.SUPPORTED_VERSIONS:
            raise RuntimeError(f'Pyth.Network version not supported: {version}')

        return data

    def read_pyth_acct_data(self, acc_addrs: Union[List[SolPubKey], SolPubKey]):
        """
        Method is possible to read one or more account data from blockchain
        Given SolPubKey as argument, method will return account data as bytes or None in case if account not found
            OR throw error otherwise (e.g. wrong account data format)
        Given list SolPubKeys as argument, method will return mapping of account addresses to bytes or Nones (for not found accounts)
            OR throw error otherwise  (e.g. wrong account data format)
        """

        if isinstance(acc_addrs, SolPubKey):
            acct_values = self.solana.get_account_info(acc_addrs)
        elif isinstance(acc_addrs, list):
            acct_values = self.solana.get_account_info_list(acc_addrs)
        else:
            raise Exception(f'Unsupported argument to read_pyth_acct_data: {acc_addrs}')

        if isinstance(acc_addrs, SolPubKey):
            # One SolPubKey given
            return self.parse_pyth_account_data(acc_addrs, acct_values)

        # Several accounts given
        if not isinstance(acct_values, list) or len(acct_values) != len(acc_addrs):
            raise RuntimeError(f'Wrong result.value field in response to getMultipleAccounts')

        return {
            str(acct_addr):
                self.parse_pyth_account_data(acct_addr, acct_value)
                for acct_addr, acct_value in zip(acc_addrs, acct_values)
        }

    def parse_mapping_account(self, acc_addr: SolPubKey):
        products = []
        while acc_addr != SYS_PROGRAM_ID:
            data = self.read_pyth_acct_data(acc_addr)
            if data is None:
                raise Exception(f"Failed to read mapping account {acc_addr}")

            num_products = unpack(self.mapping_account_layout, data, 'num_products')
            acc_addr = unpack(self.mapping_account_layout, data, 'next')
            for i in range(num_products):
                products.append(unpack(self.mapping_account_layout, data, 'product', i))
        return products

    def parse_prod_account(self, acc_data: bytes):
        return {
            'price_acc': unpack(self.product_account_layout, acc_data, 'price_acc'),
            'attrs': unpack(self.product_account_layout, acc_data, 'attrs')
        }

    def parse_price_account(self, acc_addr: SolPubKey):
        data = self.read_pyth_acct_data(acc_addr)
        if data is None:
            raise Exception(f"Failed to read price account {acc_addr}")

        price = Decimal(unpack(self.price_account_layout, data, 'agg.price'))
        conf = Decimal(unpack(self.price_account_layout, data, 'agg.conf'))
        multiply = pow(Decimal(10), unpack(self.price_account_layout, data, 'expo'))
        return {
            'valid_slot':   unpack(self.price_account_layout, data, 'valid_slot'),
            'price':        price * multiply,
            'conf':         conf * multiply,
            'status':       unpack(self.price_account_layout, data, 'agg.status')
        }

    def update_mapping(self, mapping_acc: SolPubKey):
        """
        Reads pyth.network mapping account and prepares mapping
        symbol -> price_acc_addr
        """
        self.info('Start updating Pyth.Network mapping data...')
        product_accts = self.parse_mapping_account(mapping_acc)
        products = self.read_pyth_acct_data(product_accts)
        for acct_addr, product_data in products.items():
            if product_data is None:
                self.warning(f'Failed to read product account: {acct_addr}')
                continue

            try:
                product = self.parse_prod_account(product_data)
                symbol = product['attrs']['symbol']
                self.info(f'Product account {acct_addr}: {symbol}')
                self.price_accounts[symbol] = product['price_acc']
            except BaseException as exc:
                self.error(f'Failed to parse product account data {acct_addr}.', exc_info=exc)
        self.info('Pyth.Network update finished.\n\n\n')

    def get_price(self, symbol: str) -> Optional[Dict[str, Any]]:
        """
        Return price data given product symbol.
        Throws exception if symbol is absent in preloaded product map
        or error occured when loading/parsing price account
        """
        price_account = self.price_accounts.get(symbol, None)
        if price_account is None:
            return None
        return self.parse_price_account(price_account)

    def has_price(self, symbol: str) -> bool:
        return symbol in self.price_accounts
