from __future__ import annotations

import base58
import base64
import time
import traceback
import requests
import json

from typing import Optional

from solana.blockhash import Blockhash
from solana.publickey import PublicKey
from solana.rpc.api import Client as SolanaClient
from solana.account import Account as SolanaAccount
from solana.rpc.types import RPCResponse
from solana.transaction import Transaction
from itertools import zip_longest
from logged_groups import logged_group
from typing import Dict, Union, Any, List, NamedTuple, cast
from base58 import b58decode, b58encode

from .utils import SolanaBlockInfo
from ..environment import EVM_LOADER_ID, CONFIRMATION_CHECK_DELAY
from ..environment import FUZZING_BLOCKHASH, CONFIRM_TIMEOUT, FINALIZED
from ..environment import RETRY_ON_FAIL

from ..common_neon.layouts import ACCOUNT_INFO_LAYOUT, STORAGE_ACCOUNT_INFO_LAYOUT
from ..common_neon.address import EthereumAddress, ether2program
from ..common_neon.utils import get_from_dict


class AccountInfo(NamedTuple):
    tag: int
    lamports: int
    owner: PublicKey
    data: bytes


class NeonAccountInfo(NamedTuple):
    ether: str
    nonce: int
    trx_count: int
    balance: int
    code_account: PublicKey
    is_rw_blocked: bool
    ro_blocked_cnt: int

    @staticmethod
    def frombytes(data) -> NeonAccountInfo:
        cont = ACCOUNT_INFO_LAYOUT.parse(data)
        return NeonAccountInfo(
            ether=cont.ether.hex(),
            nonce=cont.nonce,
            trx_count=int.from_bytes(cont.trx_count, "little"),
            balance=int.from_bytes(cont.balance, "little"),
            code_account=PublicKey(cont.code_account),
            is_rw_blocked=(cont.is_rw_blocked != 0),
            ro_blocked_cnt=cont.ro_blocked_cnt
        )


class StorageAccountInfo(NamedTuple):
    tag: int
    caller: str
    nonce: int
    gas_limit: int
    gas_price: int
    slot: int
    operator: PublicKey
    account_list_len: int
    executor_data_size: int
    evm_data_size: int
    gas_used_and_paid: int
    number_of_payments: int
    sign: bytes
    account_list: [str]

    @staticmethod
    def frombytes(data) -> StorageAccountInfo:
        storage = STORAGE_ACCOUNT_INFO_LAYOUT.parse(data)

        account_list = []
        offset = STORAGE_ACCOUNT_INFO_LAYOUT.sizeof()
        for _ in range(storage.account_list_len):
            writable = (data[offset] > 0)
            offset += 1

            some_pubkey = PublicKey(data[offset:offset + 32])
            offset += 32

            account_list.append((writable, str(some_pubkey)))

        return StorageAccountInfo(
            tag=storage.tag,
            caller=storage.caller.hex(),
            nonce=storage.nonce,
            gas_limit=int.from_bytes(storage.gas_limit, "little"),
            gas_price=int.from_bytes(storage.gas_price, "little"),
            slot=storage.slot,
            operator=PublicKey(storage.operator),
            account_list_len=storage.account_list_len,
            executor_data_size=storage.executor_data_size,
            evm_data_size=storage.evm_data_size,
            gas_used_and_paid=int.from_bytes(storage.gas_used_and_paid, "little"),
            number_of_payments=storage.number_of_payments,
            sign=storage.sign,
            account_list=account_list
        )


class SendResult(NamedTuple):
    error: dict
    result: Optional[str]


@logged_group("neon.Proxy")
class SolanaInteractor:
    def __init__(self, solana_url: str) -> None:
        self._client = SolanaClient(solana_url)._provider
        self._fuzzing_hash_cycle = False

    def _make_request(self, request) -> RPCResponse:
        """This method is used to make retries to send request to Solana"""

        headers = {
            "Content-Type": "application/json"
        }
        client = self._client

        retry = 0
        while True:
            try:
                retry += 1
                raw_response = client.session.post(client.endpoint_uri, headers=headers, json=request)
                raw_response.raise_for_status()
                return raw_response

            except requests.exceptions.RequestException as err:
                if retry > RETRY_ON_FAIL:
                    raise

                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.error(f'Connection exception({retry}) on send request to Solana. ' +
                           f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')
                time.sleep(1)

            except Exception as err:
                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.error('Unknown exception on send request to Solana. ' +
                           f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')
                raise

    def _send_rpc_request(self, method: str, *params: Any) -> RPCResponse:
        request_id = next(self._client._request_counter) + 1

        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params
        }
        raw_response = self._make_request(request)
        return cast(RPCResponse, raw_response.json())

    def _send_rpc_batch_request(self, method: str, params_list: List[Any]) -> List[RPCResponse]:
        full_request_data = []
        full_response_data = []
        request_data = []
        client = self._client

        for params in params_list:
            request_id = next(client._request_counter) + 1
            request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            request_data.append(request)
            full_request_data.append(request)

            # Protection from big payload
            if len(request_data) >= 25 or len(full_request_data) == len(params_list):
                raw_response = self._make_request(request_data)
                response_data = cast(List[RPCResponse], raw_response.json())

                full_response_data += response_data
                request_data.clear()

        full_response_data.sort(key=lambda r: r["id"])

        for request, response in zip_longest(full_request_data, full_response_data):
            # self.debug(f'Request: {request}')
            # self.debug(f'Response: {response}')
            if request["id"] != response["id"]:
                raise RuntimeError(f"Invalid RPC response: request {request} response {response}")

        return full_response_data

    def get_cluster_nodes(self) -> [dict]:
        return self._send_rpc_request("getClusterNodes").get('result', [])

    def get_slots_behind(self) -> Optional[int]:
        response = self._send_rpc_request('getHealth')
        status = response.get('result')
        if status == 'ok':
            return 0
        slots_behind = get_from_dict(response, 'error', 'data', 'numSlotsBehind')
        if slots_behind:
            return int(slots_behind)
        return None

    def get_signatures_for_address(self, before: Optional[str], limit: int, commitment='confirmed') -> []:
        opts: Dict[str, Union[int, str]] = {}
        if before is not None:
            opts["before"] = before
        opts["limit"] = limit
        opts["commitment"] = commitment

        return self._send_rpc_request("getSignaturesForAddress", EVM_LOADER_ID, opts)

    def get_confirmed_transaction(self, sol_sign: str, encoding: str = "json"):
        return self._send_rpc_request("getConfirmedTransaction", sol_sign, encoding)

    def get_slot(self, commitment='confirmed') -> RPCResponse:
        opts = {
            'commitment': commitment
        }
        return self._send_rpc_request('getSlot', opts)

    def get_account_info(self, pubkey: PublicKey, length=256, commitment='confirmed') -> Optional[AccountInfo]:
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
        owner = info['owner']

        return AccountInfo(account_tag, lamports, owner, data)

    def get_account_info_list(self, accounts: [PublicKey], length=256, commitment='confirmed') -> [AccountInfo]:
        opts = {
            "encoding": "base64",
            "commitment": commitment,
        }

        if length != 0:
            opts['dataSlice'] = {
                'offset': 0,
                'length': length
            }

        result = self._send_rpc_request("getMultipleAccounts", [str(a) for a in accounts], opts)
        # self.debug(f"{json.dumps(result, sort_keys=True)}")

        if result['result']['value'] is None:
            self.debug(f"Can't get information about {accounts}")
            return []

        accounts_info = []
        for pubkey, info in zip(accounts, result['result']['value']):
            if info is None:
                accounts_info.append(None)
            else:
                data = base64.b64decode(info['data'][0])
                account = AccountInfo(tag=data[0], lamports=info['lamports'], owner=info['owner'], data=data)
                accounts_info.append(account)

        return accounts_info

    def get_sol_balance(self, account, commitment='confirmed') -> int:
        opts = {
            "commitment": commitment
        }
        return self._send_rpc_request('getBalance', str(account), opts)['result']['value']

    def get_sol_balance_list(self, accounts_list: List[Union[str, PublicKey]], commitment='confirmed') -> List[int]:
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

    def get_token_account_balance(self, pubkey: Union[str, PublicKey], commitment='confirmed') -> int:
        opts = {
            "commitment": commitment
        }
        response = self._send_rpc_request("getTokenAccountBalance", str(pubkey), opts)
        result = response.get('result', None)
        if result is None:
            return 0
        return int(result['value']['amount'])

    def get_token_account_balance_list(self, pubkey_list: [Union[str, PublicKey]], commitment: object = 'confirmed') -> [int]:
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

    def get_neon_account_info(self, eth_account: EthereumAddress) -> Optional[NeonAccountInfo]:
        account_sol, nonce = ether2program(eth_account)
        info = self.get_account_info(account_sol)
        if info is None:
            return None
        elif len(info.data) < ACCOUNT_INFO_LAYOUT.sizeof():
            raise RuntimeError(f"Wrong data length for account data {account_sol}: " +
                               f"{len(info.data)} < {ACCOUNT_INFO_LAYOUT.sizeof()}")
        return NeonAccountInfo.frombytes(info.data)

    def get_storage_account_info(self, storage_account: PublicKey) -> Optional[StorageAccountInfo]:
        info = self.get_account_info(storage_account, length=0)
        if info is None:
            return None
        elif info.tag != 30:
            self.debug(f'Storage account {str(storage_account)} has tag {info.tag}')
            return None
        elif len(info.data) < STORAGE_ACCOUNT_INFO_LAYOUT.sizeof():
            raise RuntimeError(f"Wrong data length for storage data {storage_account}: " +
                               f"{len(info.data)} < {STORAGE_ACCOUNT_INFO_LAYOUT.sizeof()}")
        return StorageAccountInfo.frombytes(info.data)

    def get_account_info_layout_list(self, eth_accounts: List[EthereumAddress]) -> List[Optional[AccountInfoLayout]]:
        requests_list = []
        for eth_account in eth_accounts:
            account_sol, _nonce = ether2program(eth_account)
            requests_list.append(account_sol)
        responses_list = self.get_account_info_list(requests_list)
        accounts_list = []
        for info in responses_list:
            if info is None or len(info.data) < ACCOUNT_INFO_LAYOUT.sizeof():
                accounts_list.append(None)
                continue
            accounts_list.append(AccountInfoLayout.frombytes(info.data))
        return accounts_list

    def get_multiple_rent_exempt_balances_for_size(self, size_list: [int], commitment='confirmed') -> [int]:
        opts = {
            "commitment": commitment
        }
        request_list = [(size, opts) for size in size_list]
        response_list = self._send_rpc_batch_request("getMinimumBalanceForRentExemption", request_list)
        return [r['result'] for r in response_list]

    def get_block_slot_list(self, last_block_slot, limit: int, commitment='confirmed') -> [int]:
        opts = {
            "commitment": commitment,
            "enconding": "json",
        }
        return self._send_rpc_request("getBlocksWithLimit", last_block_slot, limit, opts)['result']

    def get_block_info(self, slot: int, commitment='confirmed') -> [SolanaBlockInfo]:
        opts = {
            "commitment": commitment,
            "encoding": "json",
            "transactionDetails": "signatures",
            "rewards": False
        }

        response = self._send_rpc_request('getBlock', slot, opts)
        net_block = response.get('result', None)
        if not net_block:
            return SolanaBlockInfo(slot=slot)

        return SolanaBlockInfo(
            slot=slot,
            is_finalized=(commitment == FINALIZED),
            hash='0x' + base58.b58decode(net_block['blockhash']).hex(),
            parent_hash='0x' + base58.b58decode(net_block['previousBlockhash']).hex(),
            time=net_block['blockTime'],
            signs=net_block['signatures']
        )

    def get_block_info_list(self, block_slot_list: [int], commitment='confirmed') -> [SolanaBlockInfo]:
        block_list = []
        if not len(block_slot_list):
            return block_list

        opts = {
            "commitment": commitment,
            "encoding": "json",
            "transactionDetails": "signatures",
            "rewards": False
        }

        request_list = []
        for slot in block_slot_list:
            request_list.append((slot, opts))

        response_list = self._send_rpc_batch_request('getBlock', request_list)
        for slot, response in zip(block_slot_list, response_list):
            if (not response) or ('result' not in response):
                block = SolanaBlockInfo(
                    slot=slot,
                    is_finalized=(commitment == FINALIZED),
                )
            else:
                net_block = response['result']
                block = SolanaBlockInfo(
                    slot=slot,
                    is_finalized=(commitment == FINALIZED),
                    hash='0x' + base58.b58decode(net_block['blockhash']).hex(),
                    parent_hash='0x' + base58.b58decode(net_block['previousBlockhash']).hex(),
                    time=net_block['blockTime'],
                    signs=net_block['signatures']
                )
            block_list.append(block)
        return block_list

    def get_recent_blockslot(self, commitment='confirmed') -> int:
        opts = {
            'commitment': commitment
        }
        blockhash_resp = self._send_rpc_request('getRecentBlockhash', opts)
        if not blockhash_resp["result"]:
            raise RuntimeError("failed to get recent blockhash")
        return blockhash_resp['result']['context']['slot']

    def get_recent_blockhash(self, commitment='confirmed') -> Blockhash:
        opts = {
            'commitment': commitment
        }
        blockhash_resp = self._send_rpc_request('getRecentBlockhash', opts)
        if not blockhash_resp["result"]:
            raise RuntimeError("failed to get recent blockhash")
        blockhash = blockhash_resp["result"]["value"]["blockhash"]
        return Blockhash(blockhash)

    def _fuzzing_transactions(self, signer: SolanaAccount, tx_list, tx_opts, request_list):
        """
        Make each second transaction a bad one.
        This is used to test a transaction sending on a live cluster (testnet/devnet).
        """
        if not FUZZING_BLOCKHASH:
            return request_list

        self._fuzzing_hash_cycle = not self._fuzzing_hash_cycle
        if not self._fuzzing_hash_cycle:
            return request_list

        # get bad block slot for sent transactions
        slot = self.get_recent_blockslot()
        # blockhash = '4NCYB3kRT8sCNodPNuCZo8VUh4xqpBQxsxed2wd9xaD4'
        block_opts = {
            "encoding": "json",
            "transactionDetails": "none",
            "rewards": False
        }
        slot = max(slot - 500, 10)
        block = self._send_rpc_request("getBlock", slot, block_opts)
        fuzzing_blockhash = Blockhash(block['result']['blockhash'])
        self.debug(f"fuzzing block {fuzzing_blockhash} for slot {slot}")

        # sign half of transactions with a bad blockhash
        for idx, tx in enumerate(tx_list):
            if idx % 2 == 1:
                continue
            tx.recent_blockhash = fuzzing_blockhash
            tx.sign(signer)
            base64_tx = base64.b64encode(tx.serialize()).decode('utf-8')
            request_list[idx] = (base64_tx, tx_opts)
        return request_list

    def _send_multiple_transactions(self, signer: SolanaAccount, tx_list: [Transaction],
                                    skip_preflight: bool, preflight_commitment: str) -> [str]:
        opts = {
            "skipPreflight": skip_preflight,
            "encoding": "base64",
            "preflightCommitment": preflight_commitment
        }

        blockhash = None
        request_list = []

        for tx in tx_list:
            if not tx.recent_blockhash:
                if not blockhash:
                    blockhash = self.get_recent_blockhash()
                tx.recent_blockhash = blockhash
                tx.signatures.clear()
            if not tx.signatures:
                tx.sign(signer)
            base64_tx = base64.b64encode(tx.serialize()).decode('utf-8')
            request_list.append((base64_tx, opts))

        request_list = self._fuzzing_transactions(signer, tx_list, opts, request_list)
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
                if get_from_dict(error, 'data', 'err') == 'AlreadyProcessed':
                    result = b58encode(tx.signature()).decode("utf-8")
                    self.debug(f'Transaction is already processed: {str(result)}')
                    error = None
                else:
                    self.debug(f'Got error on transaction execution: {json.dumps(error)}')
                    result = None

            result_list.append(SendResult(result=result, error=error))
        return result_list

    def send_multiple_transactions(self, signer: SolanaAccount, tx_list: [], waiter,
                                   skip_preflight: bool, preflight_commitment: str) -> [{}]:
        send_result_list = self._send_multiple_transactions(signer, tx_list, skip_preflight, preflight_commitment)
        # Filter good transactions and wait the confirmations for them
        sign_list = [s.result for s in send_result_list if s.result]
        self._confirm_multiple_transactions(sign_list, waiter)
        # Get receipts for good transactions
        confirmed_list = self._get_multiple_receipts(sign_list)
        # Mix errors with receipts for good transactions
        receipt_list = []
        for s in send_result_list:
            if s.error:
                receipt_list.append(s.error)
            else:
                receipt_list.append(confirmed_list.pop(0))

        return receipt_list

    def _confirm_multiple_transactions(self, sign_list: [str], waiter=None):
        """Confirm a transaction."""
        if not len(sign_list):
            self.debug('No confirmations, because transaction list is empty')
            return

        opts = {
            "searchTransactionHistory": False
        }

        elapsed_time = 0
        while elapsed_time < CONFIRM_TIMEOUT:
            if elapsed_time > 0:
                time.sleep(CONFIRMATION_CHECK_DELAY)
            elapsed_time += CONFIRMATION_CHECK_DELAY

            response = self._send_rpc_request("getSignatureStatuses", sign_list, opts)
            result = response.get('result', None)
            if not result:
                continue

            if waiter:
                slot = result['context']['slot']
                waiter.on_wait_confirm(elapsed_time, slot)

            for status in result['value']:
                if not status:
                    break
                if status['confirmationStatus'] == 'processed':
                    break
            else:
                self.debug(f'Got confirmed status for transactions: {sign_list}')
                return

        self.warning(f'No confirmed status for transactions: {sign_list}')

    def _get_multiple_receipts(self, sign_list: [str]) -> [Any]:
        if not len(sign_list):
            return []
        opts = {"encoding": "json", "commitment": "confirmed"}
        request_list = [(sign, opts) for sign in sign_list]
        response_list = self._send_rpc_batch_request("getTransaction", request_list)
        return [r.get('result') for r in response_list]
