from __future__ import annotations

import base64
from dataclasses import dataclass
import itertools
import json
import time
from typing import Dict, Union, Any, List, Optional, Set, cast
import logging
import base58
import requests

from .address import NeonAddress, neon_2program
from .config import Config
from .constants import NEON_ACCOUNT_TAG
from .errors import SolanaUnavailableError
from .layouts import ACCOUNT_INFO_LAYOUT
from .solana_tx import SolTx, SolBlockHash, SolPubKey, SolCommit
from .solana_tx_error_parser import SolTxErrorParser
from .utils import SolBlockInfo
from .layouts import HolderAccountInfo, AccountInfo, NeonAccountInfo, ALTAccountInfo


LOG = logging.getLogger(__name__)
RPCResponse = Dict[str, Any]


@dataclass(frozen=True)
class SolRecentBlockHash:
    block_hash: SolBlockHash
    last_valid_block_height: int


@dataclass(frozen=True)
class SolSendResult:
    error: Dict[str, Any]
    result: Optional[str]


@dataclass(frozen=True)
class SolSigStatus:
    sol_sig: str
    block_slot: Optional[int]
    commitment: SolCommit.Type

    @staticmethod
    def init_empty(sol_sig: str) -> SolSigStatus:
        return SolSigStatus(sol_sig=sol_sig, block_slot=None, commitment=SolCommit.NotProcessed)


@dataclass(frozen=True)
class SolBlockStatus:
    block_slot: int
    commitment: SolCommit.Type

    @staticmethod
    def init_empty(block_slot: int) -> SolBlockStatus:
        return SolBlockStatus(block_slot=block_slot, commitment=SolCommit.NotProcessed)


class SolInteractor:
    def __init__(self, config: Config, solana_url: str) -> None:
        self._config = config
        self._request_cnt = itertools.count()
        self._endpoint_uri = solana_url
        self._session = requests.sessions.Session()

    def _simple_send_post_request(self, request) -> requests.Response:
        headers = {
            'Content-Type': 'application/json'
        }

        raw_response = self._session.post(self._endpoint_uri, headers=headers, json=request)
        raw_response.raise_for_status()
        return raw_response

    def _send_post_request(self, request: Union[List[Dict[str, Any]], Dict[str, Any]]) -> requests.Response:
        """This method is used to make retries to send request to Solana"""

        retry = 0
        while True:
            try:
                retry += 1
                return self._simple_send_post_request(request)

            except requests.exceptions.RequestException as exc:
                # Hide the Solana URL
                str_err = str(exc).replace(self._endpoint_uri, 'XXXXX')

                if retry <= self._config.retry_on_fail:
                    LOG.debug(
                        f'Receive connection error {str_err} on connection to Solana. '
                        f'Attempt {retry + 1} to send the request to Solana node...'
                    )
                    time.sleep(1)
                    continue

                LOG.warning(f'Connection exception on send request to Solana. Retry {retry}: {str_err}')
                raise SolanaUnavailableError(str_err)

            except BaseException as exc:
                str_err = str(exc).replace(self._endpoint_uri, 'XXXXX')
                LOG.error(f'Unknown exception on send request to Solana: {str_err}')
                raise SolanaUnavailableError(str_err)

    def _build_rpc_request(self, method: str, *param_list: Any) -> Dict[str, Any]:
        request_id = next(self._request_cnt) + 1

        return {
            'jsonrpc': '2.0',
            'id': request_id,
            'method': method,
            'params': list(param_list)
        }

    def _send_rpc_request(self, method: str, *param_list: Any) -> RPCResponse:
        request = self._build_rpc_request(method, *param_list)
        raw_response = self._send_post_request(request)
        return cast(RPCResponse, raw_response.json())

    def _simple_send_rpc_request(self, method: str, *param_list: Any) -> RPCResponse:
        request = self._build_rpc_request(method, *param_list)
        raw_response = self._simple_send_post_request(request)
        return cast(RPCResponse, raw_response.json())

    def _send_rpc_batch_request(self, method: str, params_list: List[Any]) -> List[RPCResponse]:
        full_request_list = list()
        full_response_list = list()
        request_list = list()
        request_data = ''

        for params in params_list:
            request = self._build_rpc_request(method, *params)
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

        full_response_list.sort(key=lambda r: r['id'])

        # for request, response in itertools.zip_longest(full_request_list, full_response_list):
        #     LOG.debug(f'Request: {request}')
        #     LOG.debug(f'Response: {response}')
        #     if request['id'] != response['id']:
        #         raise RuntimeError(f'Invalid RPC response: request {request} response {response}')

        return full_response_list

    def get_cluster_nodes(self) -> List[Dict[str, Any]]:
        return self._send_rpc_request('getClusterNodes').get('result', list())

    def get_slots_behind(self) -> Optional[int]:
        response = self._send_rpc_request('getHealth')
        status = response.get('result', None)
        if status == 'ok':
            return 0
        slots_behind = SolTxErrorParser(self._config.evm_program_id, response).get_slots_behind()
        if slots_behind is not None:
            return int(slots_behind)
        return None

    def is_healthy(self) -> bool:
        status = self._send_rpc_request('getHealth').get('result', 'bad')
        return status == 'ok'

    def get_sig_list_for_address(self, address: SolPubKey, before: Optional[str], limit: int,
                                 commitment=SolCommit.Confirmed) -> List[Dict[str, Any]]:
        opts = {
            'limit': limit,
            'commitment': SolCommit.to_solana(commitment)
        }

        if before:
            opts['before'] = before

        response = self._send_rpc_request('getSignaturesForAddress', str(address), opts)

        error = response.get('error', None)
        if error is not None:
            LOG.warning(f'fail to get solana signatures: {error}')

        return response.get('result', list())

    def get_block_slot(self, commitment=SolCommit.Confirmed) -> int:
        opts = {
            'commitment': SolCommit.to_solana(commitment)
        }
        return self._send_rpc_request('getSlot', opts).get('result', 0)

    @staticmethod
    def _decode_account_info(address: SolPubKey, raw_account: Dict[str, Any]) -> AccountInfo:
        data = base64.b64decode(raw_account.get('data', None)[0])
        account_tag = data[0] if len(data) > 0 else 0
        lamports = raw_account.get('lamports', 0)
        owner = SolPubKey.from_string(raw_account.get('owner', None))
        return AccountInfo(address, account_tag, lamports, owner, data)

    def get_account_info(self, pubkey: SolPubKey, length: Optional[int] = None,
                         commitment=SolCommit.Confirmed) -> Optional[AccountInfo]:
        opts = {
            'encoding': 'base64',
            'commitment': SolCommit.to_solana(commitment),
        }

        if length is not None:
            opts['dataSlice'] = {
                'offset': 0,
                'length': length
            }

        result = self._send_rpc_request('getAccountInfo', str(pubkey), opts)
        error = result.get('error')
        if error is not None:
            LOG.debug(f"Can't get information about account {str(pubkey)}: {error}")
            return None

        raw_account = result.get('result', dict()).get('value', None)
        if raw_account is None:
            LOG.debug(f"Can't get information about {str(pubkey)}")
            return None

        return self._decode_account_info(pubkey, raw_account)

    def get_account_info_list(self, src_account_list: List[SolPubKey], length: Optional[int] = None,
                              commitment=SolCommit.Confirmed) -> List[Optional[AccountInfo]]:
        opts = {
            'encoding': 'base64',
            'commitment': SolCommit.to_solana(commitment),
        }

        if length is not None:
            opts['dataSlice'] = {
                'offset': 0,
                'length': length
            }

        account_info_list: List[Optional[AccountInfo]] = list()
        while len(src_account_list) > 0:
            account_list = [str(a) for a in src_account_list[:50]]
            src_account_list = src_account_list[50:]
            result = self._send_rpc_request('getMultipleAccounts', account_list, opts)

            error = result.get('error', None)
            if error:
                LOG.debug(f"Can't get information about accounts {account_list}: {error}")
                return account_info_list

            for pubkey, info in zip(account_list, result.get('result', dict()).get('value', None)):
                if info is None:
                    account_info_list.append(None)
                else:
                    account_info_list.append(self._decode_account_info(SolPubKey.from_string(pubkey), info))
        return account_info_list

    def get_program_account_info_list(self, program: SolPubKey, offset: int, length: int,
                                      data_offset: int, data: bytes,
                                      commitment=SolCommit.Confirmed) -> List[AccountInfo]:
        opts = {
            'encoding': 'base64',
            'commitment': SolCommit.to_solana(commitment),
            'dataSlice': {
                'offset': offset,
                'length': length
            },
            'filters': [{
                'memcmp': {
                    'offset': data_offset,
                    'bytes': base58.b58encode(data).decode('utf-8'),  # TODO: replace to base64 for version >= 1.14
                    'encoding': 'base58'
                }
            }]
        }

        try:
            response = self._simple_send_rpc_request('getProgramAccounts', str(program), opts)
        except (BaseException, ):
            LOG.debug('error on get program accounts')
            return list()

        error = response.get('error', None)
        if error is not None:
            LOG.debug(f'fail to get program accounts: {error}')
            return list()

        raw_account_list = response.get('result', list())
        account_info_list: List[AccountInfo] = list()
        for raw_account in raw_account_list:
            address = SolPubKey.from_string(raw_account.get('pubkey'))
            account_info = self._decode_account_info(address, raw_account.get('account', dict()))
            account_info_list.append(account_info)
        return account_info_list

    def get_sol_balance(self, account: Union[str, SolPubKey], commitment=SolCommit.Confirmed) -> int:
        opts = {
            'commitment': SolCommit.to_solana(commitment)
        }
        return self._send_rpc_request('getBalance', str(account), opts).get('result', dict()).get('value', 0)

    def get_sol_balance_list(self, accounts_list: List[Union[str, SolPubKey]],
                             commitment=SolCommit.Confirmed) -> List[int]:
        opts = {
            'commitment': SolCommit.to_solana(commitment)
        }
        requests_list = list()
        for account in accounts_list:
            requests_list.append([str(account), opts])

        balances_list = list()
        response_list = self._send_rpc_batch_request('getBalance', requests_list)
        for response in response_list:
            balance = response.get('result', dict()).get('value', 0)
            balances_list.append(balance)

        return balances_list

    def get_neon_account_info(self, neon_account: Union[str, bytes, NeonAddress],
                              commitment=SolCommit.Confirmed) -> Optional[NeonAccountInfo]:
        if not isinstance(neon_account, NeonAddress):
            neon_account = NeonAddress(neon_account)
        account_sol, nonce = neon_2program(self._config.evm_program_id, neon_account)
        info = self.get_account_info(account_sol, commitment=commitment)
        if info is None:
            return None

        return NeonAccountInfo.from_account_info(info)

    def get_state_tx_cnt(self, neon_account: Union[str, bytes, NeonAddress], commitment=SolCommit.Confirmed) -> int:
        neon_account_info = self.get_neon_account_info(neon_account, commitment)
        return neon_account_info.tx_count if neon_account_info is not None else 0

    def get_neon_account_info_list(self, neon_account_list: List[Union[NeonAddress, str]],
                                   commitment=SolCommit.Confirmed) -> List[Optional[NeonAccountInfo]]:
        requests_list = list()
        for neon_account in neon_account_list:
            account_sol, _nonce = neon_2program(self._config.evm_program_id, neon_account)
            requests_list.append(account_sol)
        responses_list = self.get_account_info_list(requests_list, commitment=commitment)
        accounts_list = list()
        for account_sol, info in zip(requests_list, responses_list):
            if (info is None) or (len(info.data) < ACCOUNT_INFO_LAYOUT.sizeof()) or (info.tag != NEON_ACCOUNT_TAG):
                accounts_list.append(None)
                continue
            accounts_list.append(NeonAccountInfo.from_account_info(info))
        return accounts_list

    def get_holder_account_info(self, holder_account: SolPubKey) -> Optional[HolderAccountInfo]:
        info = self.get_account_info(holder_account)
        if info is None:
            return None
        return HolderAccountInfo.from_account_info(info)

    def get_account_lookup_table_info(self, table_account: SolPubKey) -> Optional[ALTAccountInfo]:
        info = self.get_account_info(table_account)
        if info is None:
            return None
        return ALTAccountInfo.from_account_info(info)

    def get_multiple_rent_exempt_balances_for_size(self, size_list: List[int],
                                                   commitment=SolCommit.Confirmed) -> List[int]:
        opts = {
            'commitment': SolCommit.to_solana(commitment)
        }
        request_list = [[size, opts] for size in size_list]
        response_list = self._send_rpc_batch_request('getMinimumBalanceForRentExemption', request_list)
        return [r.get('result', 0) for r in response_list]

    @staticmethod
    def _decode_block_info(block_slot: int, net_block: Dict[str, Any]) -> SolBlockInfo:
        return SolBlockInfo(
            block_slot=block_slot,
            block_hash='0x' + base58.b58decode(net_block.get('blockhash', '')).hex().lower(),
            block_time=net_block.get('blockTime', None),
            block_height=net_block.get('blockHeight', None),
            parent_block_slot=net_block.get('parentSlot', None)
        )

    def get_block_info(self, block_slot: int, commitment=SolCommit.Confirmed) -> SolBlockInfo:
        opts = {
            'commitment': SolCommit.to_solana(commitment),
            'encoding': 'json',
            'transactionDetails': 'none',
            'rewards': False
        }

        response = self._send_rpc_request('getBlock', block_slot, opts)
        net_block = response.get('result', None)
        if not net_block:
            return SolBlockInfo(block_slot=block_slot)

        return self._decode_block_info(block_slot, net_block)

    def get_block_info_list(self, block_slot_list: List[int], commitment=SolCommit.Confirmed) -> List[SolBlockInfo]:
        block_list = list()
        if len(block_slot_list) == 0:
            return block_list

        opts = {
            'commitment': SolCommit.to_solana(commitment),
            'encoding': 'json',
            'transactionDetails': 'none',
            'rewards': False
        }

        request_list = [[slot, opts] for slot in block_slot_list]

        response_list = self._send_rpc_batch_request('getBlock', request_list)
        for block_slot, response in zip(block_slot_list, response_list):
            if response is None:
                block = SolBlockInfo(block_slot=block_slot)
            else:
                net_block = response.get('result', None)
                if net_block is None:
                    block = SolBlockInfo(block_slot=block_slot)
                else:
                    block = self._decode_block_info(block_slot, net_block)
            block_list.append(block)
        return block_list

    def get_recent_block_slot(self, commitment=SolCommit.Confirmed, default: Optional[int] = None) -> int:
        opts = {
            'commitment': SolCommit.to_solana(commitment)
        }
        response = self._send_rpc_request('getLatestBlockhash', opts)
        result = response.get('result', None)
        if result is None:
            if default:
                return default
            LOG.debug(f'{response}')
            raise RuntimeError('failed to get latest block hash')
        return result.get('context', dict()).get('slot', 0)

    def get_recent_block_hash(self, commitment=SolCommit.Finalized) -> SolRecentBlockHash:
        opts = {
            'commitment': SolCommit.to_solana(commitment)
        }
        response = self._send_rpc_request('getLatestBlockhash', opts)
        result = response.get('result', None)
        if result is None:
            raise RuntimeError('failed to get recent block hash')
        result = result.get('value', dict())
        block_hash = result.get('blockhash')
        last_valid_block_height = result.get('lastValidBlockHeight')
        return SolRecentBlockHash(
            block_hash=SolBlockHash.from_string(block_hash),
            last_valid_block_height=last_valid_block_height
        )

    def get_block_hash(self, block_slot: int) -> SolBlockHash:
        block_opts = {
            'encoding': 'json',
            'transactionDetails': 'none',
            'rewards': False
        }

        block = self._send_rpc_request('getBlock', block_slot, block_opts)
        return SolBlockHash.from_string(block.get('result', dict()).get('blockhash', None))

    def get_block_height(self, block_slot: Optional[int] = None, commitment=SolCommit.Confirmed) -> int:
        opts = {
            'commitment': SolCommit.to_solana(commitment)
        }
        if block_slot is None:
            block_height_resp = self._send_rpc_request('getBlockHeight', opts)
            block_height = block_height_resp.get('result', None)
        else:
            block_height = self.get_block_info(block_slot, commitment).block_height
        return block_height if block_height is not None else 0

    def send_tx_list(self, tx_list: List[SolTx], skip_preflight: bool) -> List[SolSendResult]:
        opts = {
            'skipPreflight': skip_preflight,
            'encoding': 'base64',
            'preflightCommitment': SolCommit.Processed
        }

        request_list = list()
        for tx in tx_list:
            base64_tx = base64.b64encode(tx.serialize()).decode('utf-8')
            request_list.append((base64_tx, opts))

        response_list = self._send_rpc_batch_request('sendTransaction', request_list)
        result_list = list()

        for response, tx in zip(response_list, tx_list):
            raw_result = response.get('result', None)

            result = None
            if isinstance(raw_result, dict):
                LOG.debug(f'Got strange result on transaction execution: {raw_result}')
            elif isinstance(raw_result, str):
                result = base58.b58encode(base58.b58decode(raw_result)).decode('utf-8')
            elif isinstance(raw_result, bytes):
                result = base58.b58encode(raw_result).decode('utf-8')
            elif raw_result is not None:
                LOG.debug(f'Got strange result on transaction execution: {str(raw_result)}')

            error = response.get('error', None)
            if error:
                if SolTxErrorParser(self._config.evm_program_id, error).check_if_already_processed():
                    result = str(tx.sig)
                    LOG.debug(f'Transaction is already processed: {str(result)}')
                    error = None
                else:
                    # LOG.debug(f'Got error on transaction execution: {error}')
                    result = None

            result_list.append(SolSendResult(result=result, error=error))
        return result_list

    @staticmethod
    def _get_block_status(block_slot: int,
                          finalized_block_info: SolBlockInfo,
                          block_commitment: Dict[str, Any]) -> SolBlockStatus:
        if not finalized_block_info.is_empty():
            return SolBlockStatus(block_slot, SolCommit.Finalized)

        result = block_commitment.get('result', None)
        if result is None:
            return SolBlockStatus.init_empty(block_slot)

        commitment_list = result.get('commitment', None)
        if commitment_list is None:
            return SolBlockStatus.init_empty(block_slot)

        voted_stake = sum(commitment_list)
        total_stake = result.get('totalStake', 1)

        if (voted_stake * 100 / total_stake) > 66.67:
            return SolBlockStatus(block_slot, SolCommit.Safe)

        return SolBlockStatus(block_slot, SolCommit.Confirmed)

    def get_block_status(self, block_slot: int) -> SolBlockStatus:
        finalized_block_info = self.get_block_info(block_slot, commitment=SolCommit.Finalized)
        response = self._send_rpc_request('getBlockCommitment', block_slot)
        return self._get_block_status(block_slot, finalized_block_info, response)

    def check_confirm_of_tx_sig_list(self, tx_sig_list: List[str],
                                     commit_set: Set[SolCommit.Type],
                                     valid_block_height: int) -> bool:
        if len(tx_sig_list) == 0:
            return True

        block_height = self.get_block_height()
        if block_height >= valid_block_height:
            search_in_history = True
        else:
            search_in_history = False

        opts = {
            'searchTransactionHistory': search_in_history
        }
        limit = 100

        while len(tx_sig_list) > 0:
            (part_tx_sig_list, tx_sig_list) = (tx_sig_list[:limit], tx_sig_list[limit:])
            response = self._send_rpc_request('getSignatureStatuses', part_tx_sig_list, opts)

            status_list = response.get('result', dict()).get('value', list())
            if len(status_list) == 0:
                return False

            for status in status_list:
                if not status:
                    return False
                elif status.get('confirmationStatus', '') not in commit_set:
                    return False
        return True

    def get_tx_receipt_list(self, tx_sig_list: List[str],
                            commitment: SolCommit.Type) -> List[Optional[Dict[str, Any]]]:
        if len(tx_sig_list) == 0:
            return list()

        opts = {
            'encoding': 'json',
            'commitment': SolCommit.to_solana(commitment),
            'maxSupportedTransactionVersion': 0
        }
        request_list = [[tx_sig, opts] for tx_sig in tx_sig_list]
        response_list = self._send_rpc_batch_request('getTransaction', request_list)
        return [r.get('result', None) for r in response_list]
