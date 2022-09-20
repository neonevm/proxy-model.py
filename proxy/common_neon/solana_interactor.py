from __future__ import annotations

import math

import base58
import base64
import time
import traceback
import requests
import itertools
import json

from solana.rpc.types import RPCResponse

from logged_groups import logged_group
from typing import Dict, Union, Any, List, Optional, Tuple, cast
from base58 import b58decode, b58encode
from dataclasses import dataclass

from ..common_neon.utils import SolanaBlockInfo
from ..common_neon.solana_transaction import SolTx, SolBlockhash, SolPubKey
from ..common_neon.layouts import ACCOUNT_INFO_LAYOUT, CODE_ACCOUNT_INFO_LAYOUT
from ..common_neon.layouts import STORAGE_ACCOUNT_INFO_LAYOUT, FINALIZED_STORAGE_ACCOUNT_INFO_LAYOUT
from ..common_neon.layouts import HOLDER_ACCOUNT_INFO_LAYOUT
from ..common_neon.layouts import ACCOUNT_LOOKUP_TABLE_LAYOUT
from ..common_neon.constants import CONTRACT_ACCOUNT_TAG, NEON_ACCOUNT_TAG, LOOKUP_ACCOUNT_TAG
from ..common_neon.constants import ACTIVE_STORAGE_TAG, FINALIZED_STORAGE_TAG, HOLDER_TAG
from ..common_neon.solana_tx_error_parser import SolTxErrorParser
from ..common_neon.address import EthereumAddress, ether2program
from ..common_neon.utils import get_from_dict
from ..common_neon.errors import SolanaUnavailableError
from ..common_neon.config import Config


@dataclass
class AccountInfo:
    tag: int
    lamports: int
    owner: SolPubKey
    data: bytes


@dataclass
class NeonAccountInfo:
    pda_address: SolPubKey
    ether: str
    nonce: int
    tx_count: int
    balance: int
    code_account: Optional[SolPubKey]
    is_rw_blocked: bool
    ro_blocked_cnt: int

    @staticmethod
    def frombytes(pda_address: SolPubKey, data: bytes) -> NeonAccountInfo:
        cont = ACCOUNT_INFO_LAYOUT.parse(data)

        code_account = None
        if cont.code_account != bytes().rjust(SolPubKey.LENGTH, b"\0"):
            code_account = SolPubKey(cont.code_account)

        return NeonAccountInfo(
            pda_address=pda_address,
            ether=cont.ether.hex(),
            nonce=cont.nonce,
            tx_count=int.from_bytes(cont.tx_count, "little"),
            balance=int.from_bytes(cont.balance, "little"),
            code_account=code_account,
            is_rw_blocked=(cont.is_rw_blocked != 0),
            ro_blocked_cnt=cont.ro_blocked_cnt
        )


@dataclass
class NeonCodeInfo:
    pda_address: SolPubKey
    owner: SolPubKey
    code_size: int
    generation: int
    code: Optional[str]

    @staticmethod
    def frombytes(pda_address: SolPubKey, data: bytes) -> NeonCodeInfo:
        cont = CODE_ACCOUNT_INFO_LAYOUT.parse(data)

        offset = CODE_ACCOUNT_INFO_LAYOUT.sizeof()
        code = None
        if len(data) >= offset + cont.code_size:
            code = '0x' + data[offset:][:cont.code_size].hex()

        return NeonCodeInfo(
            pda_address=pda_address,
            owner=SolPubKey(cont.owner),
            code_size=cont.code_size,
            generation=cont.generation,
            code=code
        )


@dataclass
class HolderAccountInfo:
    holder_account: SolPubKey
    tag: int
    owner: SolPubKey
    neon_tx_sig: str
    neon_tx_data: Optional[bytes]
    caller: Optional[str]
    gas_limit: Optional[int]
    gas_price: Optional[int]
    gas_used: Optional[int]
    operator: Optional[SolPubKey]
    block_slot: Optional[int]
    account_list_len: Optional[int]
    account_list: Optional[List[Tuple[bool, str]]]

    @staticmethod
    def frombytes(holder_account: SolPubKey, data: bytes) -> Optional[HolderAccountInfo]:
        if len(data) < 1:
            return None
        tag = data[0]
        if tag == ACTIVE_STORAGE_TAG:
            return HolderAccountInfo._decode_storage_account(holder_account, data)
        elif tag == FINALIZED_STORAGE_TAG:
            return HolderAccountInfo._decode_finalized_storage_account(holder_account, data)
        elif tag == HOLDER_TAG:
            return HolderAccountInfo._decode_holder_account(holder_account, data)
        else:
            return None

    @staticmethod
    def _decode_storage_account(holder_account: SolPubKey, data: bytes) -> Optional[HolderAccountInfo]:
        if len(data) < STORAGE_ACCOUNT_INFO_LAYOUT.sizeof():
            return None

        storage = STORAGE_ACCOUNT_INFO_LAYOUT.parse(data)

        account_list: List[Tuple[bool, str]] = []
        offset = STORAGE_ACCOUNT_INFO_LAYOUT.sizeof()
        for _ in range(storage.account_list_len):
            writable = (data[offset] > 0)
            offset += 1

            some_pubkey = SolPubKey(data[offset:offset + SolPubKey.LENGTH])
            offset += SolPubKey.LENGTH

            account_list.append((writable, str(some_pubkey)))

        return HolderAccountInfo(
            holder_account=holder_account,
            tag=storage.tag,
            owner=SolPubKey(storage.owner),
            neon_tx_sig='0x' + storage.neon_tx_sig.hex().lower(),
            neon_tx_data=None,
            caller=storage.caller.hex(),
            gas_limit=int.from_bytes(storage.gas_limit, "little"),
            gas_price=int.from_bytes(storage.gas_price, "little"),
            gas_used=int.from_bytes(storage.gas_used, "little"),
            operator=SolPubKey(storage.operator),
            block_slot=storage.block_slot,
            account_list_len=storage.account_list_len,
            account_list=account_list
        )

    @staticmethod
    def _decode_finalized_storage_account(holder_account: SolPubKey, data: bytes) -> Optional[HolderAccountInfo]:
        if len(data) < FINALIZED_STORAGE_ACCOUNT_INFO_LAYOUT.sizeof():
            return None

        storage = FINALIZED_STORAGE_ACCOUNT_INFO_LAYOUT.parse(data)

        return HolderAccountInfo(
            holder_account=holder_account,
            tag=storage.tag,
            owner=SolPubKey(storage.owner),
            neon_tx_sig='0x' + storage.neon_tx_sig.hex().lower(),
            neon_tx_data=None,
            caller=None,
            gas_limit=None,
            gas_price=None,
            gas_used=None,
            operator=None,
            block_slot=None,
            account_list_len=None,
            account_list=None
        )

    @staticmethod
    def _decode_holder_account(holder_account: SolPubKey, data: bytes) -> Optional[HolderAccountInfo]:
        if len(data) < HOLDER_ACCOUNT_INFO_LAYOUT.sizeof():
            return None

        holder = HOLDER_ACCOUNT_INFO_LAYOUT.parse(data)
        offset = HOLDER_ACCOUNT_INFO_LAYOUT.sizeof()

        neon_tx_data = data[offset:]

        return HolderAccountInfo(
            holder_account=holder_account,
            tag=holder.tag,
            owner=SolPubKey(holder.owner),
            neon_tx_sig='0x' + holder.neon_tx_sig.hex().lower(),
            neon_tx_data=neon_tx_data,
            caller=None,
            gas_limit=None,
            gas_price=None,
            gas_used=None,
            operator=None,
            block_slot=None,
            account_list_len=None,
            account_list=None
        )


@dataclass
class ALTAccountInfo:
    type: int
    table_account: SolPubKey
    deactivation_slot: int
    last_extended_slot: int
    last_extended_slot_start_index: int
    authority: Optional[SolPubKey]
    account_key_list: List[SolPubKey]

    @staticmethod
    def frombytes(table_account: SolPubKey, data: bytes) -> Optional[ALTAccountInfo]:
        lookup = ACCOUNT_LOOKUP_TABLE_LAYOUT.parse(data)
        if lookup.type != LOOKUP_ACCOUNT_TAG:
            return None

        offset = ACCOUNT_LOOKUP_TABLE_LAYOUT.sizeof()
        if (len(data) - offset) % SolPubKey.LENGTH:
            return None

        account_key_list = []
        account_key_list_len = math.ceil((len(data) - offset) / SolPubKey.LENGTH)
        for _ in range(account_key_list_len):
            some_pubkey = SolPubKey(data[offset:offset + SolPubKey.LENGTH])
            offset += SolPubKey.LENGTH
            account_key_list.append(some_pubkey)

        authority = SolPubKey(lookup.authority) if lookup.has_authority else None

        return ALTAccountInfo(
            type=lookup.type,
            table_account=table_account,
            deactivation_slot=lookup.deactivation_slot,
            last_extended_slot=lookup.last_extended_slot,
            last_extended_slot_start_index=lookup.last_extended_slot_start_index,
            authority=authority,
            account_key_list=account_key_list
        )


@dataclass
class SolSendResult:
    error: Dict[str, Any]
    result: Optional[str]


@logged_group("neon.Proxy")
class SolInteractor:
    def __init__(self, config: Config, solana_url: str) -> None:
        self._config = config
        self._request_counter = itertools.count()
        self._endpoint_uri = solana_url
        self._session = requests.sessions.Session()
        self._fuzzing_hash_cycle = False

    def _send_post_request(self, request) -> requests.Response:
        """This method is used to make retries to send request to Solana"""

        headers = {
            "Content-Type": "application/json"
        }

        retry = 0
        while True:
            try:
                retry += 1
                raw_response = self._session.post(self._endpoint_uri, headers=headers, json=request)
                raw_response.raise_for_status()
                return raw_response

            except requests.exceptions.RequestException as err:
                # Hide the Solana URL
                str_err = str(err).replace(self._endpoint_uri, 'XXXXX')

                if retry <= self._config.retry_on_fail:
                    self.debug(f'Receive connection error {str_err} on connection to Solana. ' +
                               f'Attempt {retry + 1} to send the request to Solana node...')
                    time.sleep(1)
                    continue

                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.error(f'Connection exception({retry}) on send request to Solana. Retry {retry}' +
                           f'Type(err): {type(err)}, Error: {str_err}, Traceback: {err_tb}')
                raise SolanaUnavailableError(str_err)

            except Exception as err:
                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.error('Unknown exception on send request to Solana. ' +
                           f'Type(err): {type(err)}, Error: {str(err)}, Traceback: {err_tb}')
                raise

    def _send_rpc_request(self, method: str, *params: Any) -> RPCResponse:
        request_id = next(self._request_counter) + 1

        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params
        }
        raw_response = self._send_post_request(request)
        return cast(RPCResponse, raw_response.json())

    def _send_rpc_batch_request(self, method: str, params_list: List[Any]) -> List[RPCResponse]:
        full_request_list = []
        full_response_list = []
        request_list = []
        request_data = ''

        for params in params_list:
            request_id = next(self._request_counter) + 1
            request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            request_list.append(request)
            request_data += ', ' + json.dumps(request)
            full_request_list.append(request)

            # Protection from big payload
            if len(request_data) >= 48 * 1024 or len(full_request_list) == len(params_list):
                raw_response = self._send_post_request(request_list)
                response_data = cast(List[RPCResponse], raw_response.json())

                full_response_list += response_data
                request_list.clear()
                request_data = ''

        full_response_list.sort(key=lambda r: r["id"])

        for request, response in itertools.zip_longest(full_request_list, full_response_list):
            # self.debug(f'Request: {request}')
            # self.debug(f'Response: {response}')
            if request["id"] != response["id"]:
                raise RuntimeError(f"Invalid RPC response: request {request} response {response}")

        return full_response_list

    def get_cluster_nodes(self) -> [dict]:
        return self._send_rpc_request("getClusterNodes").get('result', [])

    def get_slots_behind(self) -> Optional[int]:
        response = self._send_rpc_request('getHealth')
        status = response.get('result')
        if status == 'ok':
            return 0
        slots_behind = SolTxErrorParser(response).get_slots_behind()
        if slots_behind is not None:
            return int(slots_behind)
        return None

    def is_healthy(self) -> bool:
        status = self._send_rpc_request('getHealth').get('result', 'bad')
        return status == 'ok'

    def get_sig_list_for_address(self, address: SolPubKey,
                                 before: Optional[str], limit: int, commitment='confirmed') -> List[Dict[str, Any]]:
        opts: Dict[str, Union[int, str]] = {
            "limit": limit,
            "commitment": commitment
        }

        if before:
            opts["before"] = before

        response = self._send_rpc_request("getSignaturesForAddress", str(address), opts)

        error = response.get('error')
        if error:
            self.warning(f'fail to get solana signatures: {error}')

        return response.get('result', [])

    def get_block_slot(self, commitment='confirmed') -> int:
        opts = {
            'commitment': commitment
        }
        return self._send_rpc_request('getSlot', opts)['result']

    def get_account_info(self, pubkey: SolPubKey, length=256, commitment='processed') -> Optional[AccountInfo]:
        opts = {
            "encoding": "base64",
            "commitment": commitment,
        }

        if length != 0:
            opts['dataSlice'] = {
                'offset': 0,
                'length': length
            }

        result = self._send_rpc_request('getAccountInfo', str(pubkey), opts)
        # self.debug(f"{json.dumps(result, sort_keys=True)}")

        info = result['result']['value']
        if info is None:
            self.debug(f"Can't get information about {str(pubkey)}")
            return None

        data = base64.b64decode(info['data'][0])

        account_tag = data[0]
        lamports = info['lamports']
        owner = SolPubKey(info['owner'])

        return AccountInfo(account_tag, lamports, owner, data)

    def get_account_info_list(self, src_account_list: List[SolPubKey], length=256,
                              commitment='processed') -> List[AccountInfo]:
        opts = {
            "encoding": "base64",
            "commitment": commitment,
        }

        if length != 0:
            opts['dataSlice'] = {
                'offset': 0,
                'length': length
            }

        account_info_list = []
        while len(src_account_list) > 0:
            account_list = [str(a) for a in src_account_list[:50]]
            src_account_list = src_account_list[50:]
            result = self._send_rpc_request("getMultipleAccounts", account_list, opts)

            error = result.get('error', None)
            if error:
                self.debug(f"Can't get information about accounts {account_list}: {error}")
                return account_info_list

            for pubkey, info in zip(account_list, result['result']['value']):
                if info is None:
                    account_info_list.append(None)
                else:
                    data = base64.b64decode(info['data'][0])
                    lamports = info['lamports']
                    owner = SolPubKey(info['owner'])
                    account_info = AccountInfo(tag=data[0], lamports=lamports, owner=owner, data=data)
                    account_info_list.append(account_info)
        return account_info_list

    def get_sol_balance(self, account, commitment='processed') -> int:
        opts = {
            "commitment": commitment
        }
        return self._send_rpc_request('getBalance', str(account), opts)['result']['value']

    def get_sol_balance_list(self, accounts_list: List[Union[str, SolPubKey]], commitment='processed') -> List[int]:
        opts = {
            'commitment': commitment
        }
        requests_list = []
        for account in accounts_list:
            requests_list.append((str(account), opts))

        balances_list = []
        response_list = self._send_rpc_batch_request('getBalance', requests_list)
        for response in response_list:
            value = get_from_dict(response, 'result', 'value')
            balance = int(value) if value else 0
            balances_list.append(balance)

        return balances_list

    def get_token_account_balance(self, pubkey: Union[str, SolPubKey], commitment='processed') -> int:
        opts = {
            "commitment": commitment
        }
        response = self._send_rpc_request("getTokenAccountBalance", str(pubkey), opts)
        result = response.get('result', None)
        if result is None:
            return 0
        return int(result['value']['amount'])

    def get_token_account_balance_list(self, pubkey_list: List[Union[str, SolPubKey]],
                                       commitment: object = 'processed') -> List[int]:
        opts = {
            "commitment": commitment
        }
        request_list = []
        for pubkey in pubkey_list:
            request_list.append((str(pubkey), opts))

        balance_list = []
        response_list = self._send_rpc_batch_request('getTokenAccountBalance', request_list)
        for response in response_list:
            result = response.get('result', None)
            balance = int(result['value']['amount']) if result else 0
            balance_list.append(balance)

        return balance_list

    def get_neon_account_info(
        self, eth_account: Union[str, EthereumAddress], commitment='processed'
    ) -> Optional[NeonAccountInfo]:
        if isinstance(eth_account, str):
            eth_account = EthereumAddress(eth_account)
        account_sol, nonce = ether2program(eth_account)
        info = self.get_account_info(account_sol, commitment=commitment)
        if info is None:
            return None
        elif info.tag != NEON_ACCOUNT_TAG:
            raise RuntimeError(f"Wrong tag {info.tag} for neon account info {str(account_sol)}")
        elif len(info.data) < ACCOUNT_INFO_LAYOUT.sizeof():
            raise RuntimeError(f"Wrong data length for account data {account_sol}: " +
                               f"{len(info.data)} < {ACCOUNT_INFO_LAYOUT.sizeof()}")
        return NeonAccountInfo.frombytes(account_sol, info.data)

    def get_neon_code_info(
        self, account: Union[str, EthereumAddress, NeonAccountInfo, SolPubKey, None]
    ) -> Optional[NeonCodeInfo]:
        if isinstance(account, str) or isinstance(account, EthereumAddress):
            account = self.get_neon_account_info(account)
        if isinstance(account, NeonAccountInfo):
            account = account.code_account
        if not isinstance(account, SolPubKey):
            return None

        info = self.get_account_info(account, length=0)
        if info is None:
            return None
        elif info.tag != CONTRACT_ACCOUNT_TAG:
            raise RuntimeError(f"Wrong tag {info.tag} for code account {str(account)}")
        elif len(info.data) < CODE_ACCOUNT_INFO_LAYOUT.sizeof():
            raise RuntimeError(f"Wrong data length for account data {str(account)}: " +
                               f"{len(info.data)} < {CODE_ACCOUNT_INFO_LAYOUT.sizeof()}")
        return NeonCodeInfo.frombytes(account, info.data)

    def get_neon_account_info_list(self, eth_accounts: List[EthereumAddress]) -> List[Optional[NeonAccountInfo]]:
        requests_list = []
        for eth_account in eth_accounts:
            account_sol, _nonce = ether2program(eth_account)
            requests_list.append(account_sol)
        responses_list = self.get_account_info_list(requests_list)
        accounts_list = []
        for account_sol, info in zip(requests_list, responses_list):
            if info is None or len(info.data) < ACCOUNT_INFO_LAYOUT.sizeof() or info.tag != NEON_ACCOUNT_TAG:
                accounts_list.append(None)
                continue
            accounts_list.append(NeonAccountInfo.frombytes(account_sol, info.data))
        return accounts_list

    def get_holder_account_info(self, holder_account: SolPubKey) -> Optional[HolderAccountInfo]:
        info = self.get_account_info(holder_account, length=0)
        if info is None:
            return None
        return HolderAccountInfo.frombytes(holder_account, info.data)

    def get_account_lookup_table_info(self, table_account: SolPubKey) -> Optional[ALTAccountInfo]:
        info = self.get_account_info(table_account, length=0)
        if info is None:
            return None
        elif len(info.data) < ACCOUNT_LOOKUP_TABLE_LAYOUT.sizeof():
            raise RuntimeError(f"Wrong data length for lookup table data {str(table_account)}: " +
                               f"{len(info.data)} < {ACCOUNT_LOOKUP_TABLE_LAYOUT.sizeof()}")
        return ALTAccountInfo.frombytes(table_account, info.data)

    def get_multiple_rent_exempt_balances_for_size(self, size_list: List[int], commitment='confirmed') -> List[int]:
        opts = {
            "commitment": commitment
        }
        request_list = [(size, opts) for size in size_list]
        response_list = self._send_rpc_batch_request("getMinimumBalanceForRentExemption", request_list)
        return [r['result'] for r in response_list]

    def get_block_info(self, block_slot: int, commitment='confirmed') -> SolanaBlockInfo:
        opts = {
            "commitment": commitment,
            "encoding": "json",
            "transactionDetails": "none",
            "rewards": False
        }

        response = self._send_rpc_request('getBlock', block_slot, opts)
        net_block = response.get('result', None)
        if not net_block:
            return SolanaBlockInfo(block_slot=block_slot)

        return SolanaBlockInfo(
            block_slot=block_slot,
            block_hash='0x' + base58.b58decode(net_block['blockhash']).hex().lower(),
            block_time=net_block['blockTime'],
            parent_block_slot=net_block['parentSlot']
        )

    def get_block_info_list(self, block_slot_list: List[int], commitment='confirmed') -> List[SolanaBlockInfo]:
        block_list = []
        if not len(block_slot_list):
            return block_list

        opts = {
            "commitment": commitment,
            "encoding": "json",
            "transactionDetails": "none",
            "rewards": False
        }

        request_list = []
        for slot in block_slot_list:
            request_list.append((slot, opts))

        response_list = self._send_rpc_batch_request('getBlock', request_list)
        for block_slot, response in zip(block_slot_list, response_list):
            if (not response) or ('result' not in response):
                block = SolanaBlockInfo(block_slot=block_slot)
            else:
                net_block = response['result']
                block = SolanaBlockInfo(
                    block_slot=block_slot,
                    block_hash='0x' + base58.b58decode(net_block['blockhash']).hex().lower(),
                    block_time=net_block['blockTime'],
                    parent_block_slot=net_block['parentSlot']
                )
            block_list.append(block)
        return block_list

    def get_recent_blockslot(self, commitment='confirmed', default: Optional[int] = None) -> int:
        opts = {
            'commitment': commitment
        }
        blockhash_resp = self._send_rpc_request('getLatestBlockhash', opts)
        if not blockhash_resp.get("result"):
            if default:
                return default
            self.debug(f'{blockhash_resp}')
            raise RuntimeError("failed to get latest blockhash")
        return blockhash_resp['result']['context']['slot']

    def get_recent_blockhash(self, commitment='confirmed') -> SolBlockhash:
        opts = {
            'commitment': commitment
        }
        blockhash_resp = self._send_rpc_request('getLatestBlockhash', opts)
        if not blockhash_resp.get("result"):
            raise RuntimeError("failed to get recent blockhash")
        blockhash = blockhash_resp["result"]["value"]["blockhash"]
        return SolBlockhash(blockhash)

    def get_blockhash(self, block_slot: int) -> SolBlockhash:
        block_opts = {
            "encoding": "json",
            "transactionDetails": "none",
            "rewards": False
        }

        block = self._send_rpc_request("getBlock", block_slot, block_opts)
        return SolBlockhash(block['result']['blockhash'])

    def get_block_height(self, commitment='confirmed') -> int:
        opts = {
            'commitment': commitment
        }
        blockheight_resp = self._send_rpc_request('getBlockHeight', opts)
        return blockheight_resp['result']

    def send_tx_list(self, tx_list: List[SolTx], skip_preflight: bool) -> List[SolSendResult]:
        opts = {
            "skipPreflight": skip_preflight,
            "encoding": "base64",
            "preflightCommitment": 'processed'
        }

        request_list = []
        for tx in tx_list:
            base64_tx = base64.b64encode(tx.serialize()).decode('utf-8')
            request_list.append((base64_tx, opts))

        response_list = self._send_rpc_batch_request('sendTransaction', request_list)
        result_list = []

        for response, tx in zip(response_list, tx_list):
            raw_result = response.get('result')

            result = None
            if isinstance(raw_result, dict):
                self.debug(f'Got strange result on transaction execution: {json.dumps(raw_result)}')
            elif isinstance(raw_result, str):
                result = b58encode(b58decode(raw_result)).decode("utf-8")
            elif isinstance(raw_result, bytes):
                result = b58encode(raw_result).decode("utf-8")
            elif raw_result is not None:
                self.debug(f'Got strange result on transaction execution: {str(raw_result)}')

            error = response.get('error')
            if error:
                if SolTxErrorParser(error).check_if_already_processed():
                    result = b58encode(tx.signature()).decode("utf-8")
                    self.debug(f'Transaction is already processed: {str(result)}')
                    error = None
                else:
                    # self.debug(f'Got error on transaction execution: {json.dumps(error)}')
                    result = None

            result_list.append(SolSendResult(result=result, error=error))
        return result_list

    def get_confirmed_slot_for_tx_sig_list(self, tx_sig_list: List[str]) -> Tuple[int, bool]:
        if len(tx_sig_list) == 0:
            return 0, False

        opts = {
            "searchTransactionHistory": False
        }

        block_slot = 0
        while len(tx_sig_list) > 0:
            (part_tx_sig_list, tx_sig_list) = (tx_sig_list[:100], tx_sig_list[100:])
            response = self._send_rpc_request("getSignatureStatuses", part_tx_sig_list, opts)

            result = response.get('result', None)
            if not result:
                return block_slot, False

            block_slot = result['context']['slot']

            for status in result['value']:
                if not status:
                    return block_slot, False
                if status['confirmationStatus'] == 'processed':
                    return block_slot, False

        return block_slot, (block_slot != 0)

    def get_tx_receipt_list(self, tx_sig_list: List[str], commitment='confirmed') -> List[Optional[Dict[str, Any]]]:
        if len(tx_sig_list) == 0:
            return []

        opts = {
            "encoding": "json",
            "commitment": commitment,
            "maxSupportedTransactionVersion": 0
        }
        request_list = [(tx_sig, opts) for tx_sig in tx_sig_list]
        response_list = self._send_rpc_batch_request("getTransaction", request_list)
        return [r.get('result') for r in response_list]
