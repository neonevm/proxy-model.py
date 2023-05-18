import struct
import logging

from decimal import Decimal
from typing import List, Union, Dict, Any, Optional, Tuple

from ..common_neon.constants import SYS_PROGRAM_ID
from ..common_neon.layouts import AccountInfo
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx import SolPubKey


LOG = logging.getLogger(__name__)


def read_str(pos: int, data: bytes) -> Tuple[bytes, int]:
    length = data[pos]
    start = pos + 1
    stop = pos + 1 + length
    return data[start:stop], stop


def read_keyvalue(pos: int, data: bytes) -> Tuple[bytes, bytes, int]:
    key, pos = read_str(pos, data)
    value, pos = read_str(pos, data)
    return key, value, pos


def read_dict(data: bytes) -> Dict[str, str]:
    pos = 0
    result: Dict[str, str] = {}
    while pos < len(data):
        key, value, pos = read_keyvalue(pos, data)
        if len(key) == 0 or len(value) == 0:
            break
        result[key.decode('utf-8')] = value.decode('utf-8')
    return result


def unpack(layout_descriptor: Dict[str, Any],
           raw_data: Optional[bytes], field_name: str, index=0) -> Union[SolPubKey, Dict[str, str], int]:
    if raw_data is None:
        raise Exception(f"Field '{field_name}': raw_data is None")

    field = layout_descriptor.get(field_name, None)
    if field is None:
        raise Exception(f'Unknown field name: {field_name}')

    length = field['len']
    start_idx = field['pos'] + index * length
    stop_idx = start_idx + length
    if start_idx >= len(raw_data) or stop_idx > len(raw_data):
        raise Exception(
            f"Field '{field_name}': Index overflow: len(raw_data) = {len(raw_data)}, "
            f"start_idx = {start_idx}, stop_idx = {stop_idx}"
        )

    if field['format'] == 'acc':  # special case for Solana account address
        return SolPubKey.from_bytes(raw_data[start_idx:stop_idx])
    elif field['format'] == 'dict':  # special case for attribute mapping
        return read_dict(raw_data[start_idx:stop_idx])
    return struct.unpack(field['format'], raw_data[start_idx:stop_idx])[0]


class PythNetworkClient:
    _PYTH_MAGIC = 0xa1b2c3d4
    _PROD_ACCT_SIZE = 512
    _PROD_HDR_SIZE = 48
    _PROD_ATTR_SIZE = _PROD_ACCT_SIZE - _PROD_HDR_SIZE
    _SUPPORTED_VERSION_SET = {2}

    _base_account_layout = {
        'magic': {'pos': 0, 'len': 4, 'format': '<I'},
        'ver': {'pos': 4, 'len': 4, 'format': '<I'}
    }

    _mapping_account_layout = {
        'num_products': {'pos': 16, 'len': 4, 'format': '<I'},
        'next': {'pos': 24, 'len': 32, 'format': 'acc'},
        'product': {'pos': 56, 'len': 32, 'format': 'acc'}
    }

    _product_account_layout = {
        'magic': {'pos': 0, 'len': 4, 'format': '<I'},
        'price_acc': {'pos': 16, 'len': 32, 'format': 'acc'},
        'attrs': {'pos': 48, 'len': _PROD_ATTR_SIZE, 'format': 'dict'}
    }

    _price_account_layout = {
        'expo': {'pos': 20, 'len': 4, 'format': '<i'},
        'valid_slot': {'pos': 40, 'len': 8, 'format': '<Q'},
        'agg.price': {'pos': 208, 'len': 8, 'format': '<q'},
        'agg.conf': {'pos': 216, 'len': 8, 'format': '<Q'},
        'agg.status': {'pos': 224, 'len': 4, 'format': '<I'},
    }

    def __init__(self, solana: SolInteractor):
        self._solana = solana
        self._price_account_dict: Dict[str, SolPubKey] = {}

    def parse_pyth_account_data(self, acct_addr: SolPubKey, acct_info_value: Optional[AccountInfo]) -> Optional[bytes]:
        # it is possible when calling to getMultipleAccounts (if some accounts are absent in blockchain)
        if acct_info_value is None:
            return None

        data = acct_info_value.data
        magic = unpack(self._base_account_layout, data, 'magic')
        if magic != self._PYTH_MAGIC:
            raise RuntimeError(f'Wrong magic {magic} in account {acct_addr}')

        version = unpack(self._base_account_layout, data, 'ver')
        if version not in self._SUPPORTED_VERSION_SET:
            raise RuntimeError(f'Pyth.Network version not supported: {version}')

        return data

    def _read_pyth_acct_data(self, acc_addr_list: Union[List[SolPubKey], SolPubKey]) -> Union[bytes, Dict[str, bytes]]:
        """
        Method is possible to read one or more account data from blockchain
        Given SolPubKey as argument, method will return account data as bytes or None in case if account not found
            OR throw error otherwise (e.g. wrong account data format)
        Given list SolPubKeys as argument, method will return mapping of account addresses to bytes or Nones (for not found accounts)
            OR throw error otherwise  (e.g. wrong account data format)
        """

        if isinstance(acc_addr_list, SolPubKey):
            acct_value: Optional[AccountInfo] = self._solana.get_account_info(acc_addr_list)
            return self.parse_pyth_account_data(acc_addr_list, acct_value)

        if not isinstance(acc_addr_list, list):
            raise Exception(f'Unsupported argument to read_pyth_acct_data: {acc_addr_list}')

        acct_value_list: List[Optional[AccountInfo]] = self._solana.get_account_info_list(acc_addr_list)

        # Several accounts given
        if len(acct_value_list) != len(acc_addr_list):
            raise RuntimeError(f'Wrong result.value field in response to getMultipleAccounts')

        return {
            str(acct_addr):
                self.parse_pyth_account_data(acct_addr, acct_value)
                for acct_addr, acct_value in zip(acc_addr_list, acct_value_list)
        }

    def _parse_mapping_account(self, acc_addr: SolPubKey) -> List[SolPubKey]:
        product_list: List[SolPubKey] = []
        while acc_addr != SYS_PROGRAM_ID:
            data = self._read_pyth_acct_data(acc_addr)
            if data is None:
                raise Exception(f"Failed to read mapping account {acc_addr}")

            num_products = unpack(self._mapping_account_layout, data, 'num_products')
            acc_addr = unpack(self._mapping_account_layout, data, 'next')
            for i in range(num_products):
                product_list.append(unpack(self._mapping_account_layout, data, 'product', i))
        return product_list

    def _parse_prod_account(self, acc_data: bytes) -> Dict[str, Any]:
        return {
            'price_acc': unpack(self._product_account_layout, acc_data, 'price_acc'),
            'attrs': unpack(self._product_account_layout, acc_data, 'attrs')
        }

    def _parse_price_account(self, acc_addr: SolPubKey) -> Dict[str, Any]:
        data = self._read_pyth_acct_data(acc_addr)
        if data is None:
            raise Exception(f"Failed to read price account {acc_addr}")

        price = Decimal(unpack(self._price_account_layout, data, 'agg.price'))
        conf = Decimal(unpack(self._price_account_layout, data, 'agg.conf'))
        multiply = pow(Decimal(10), unpack(self._price_account_layout, data, 'expo'))
        return {
            'valid_slot':   unpack(self._price_account_layout, data, 'valid_slot'),
            'price':        price * multiply,
            'conf':         conf * multiply,
            'status':       unpack(self._price_account_layout, data, 'agg.status')
        }

    def update_mapping(self, mapping_acc: SolPubKey):
        """
        Reads pyth.network mapping account and prepares mapping
        symbol -> price_acc_addr
        """
        LOG.info('Start updating Pyth.Network mapping data...')
        product_acct_list: List[SolPubKey] = self._parse_mapping_account(mapping_acc)
        product_dict: Dict[str, bytes] = self._read_pyth_acct_data(product_acct_list)
        for acct_addr, product_data in product_dict.items():
            if product_data is None:
                LOG.warning(f'Failed to read product account: {acct_addr}')
                continue

            try:
                product: Dict[str, Any] = self._parse_prod_account(product_data)
                symbol: str = product['attrs']['symbol']
                LOG.info(f'Product account {acct_addr}: {symbol}')
                self.set_price_account(symbol, product['price_acc'])
            except BaseException as exc:
                LOG.error(f'Failed to parse product account data {acct_addr}', exc_info=exc)
        LOG.info('Pyth.Network update finished')

    def set_price_account(self, symbol: str, price_account: SolPubKey) -> None:
        self._price_account_dict[symbol] = price_account

    def get_price_account(self, symbol: str) -> Optional[SolPubKey]:
        return self._price_account_dict.get(symbol, None)

    def get_price(self, symbol: str) -> Optional[Dict[str, Any]]:
        """
        Return price data given product symbol.
        Throws exception if symbol is absent in preloaded product map
        or error occured when loading/parsing price account
        """
        price_account = self._price_account_dict.get(symbol, None)
        if price_account is None:
            return None
        return self._parse_price_account(price_account)

    def has_price(self, symbol: str) -> bool:
        return symbol in self._price_account_dict
