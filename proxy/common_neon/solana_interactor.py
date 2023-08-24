from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Union, Any, List, Optional, Set, cast

import base64
import itertools
import json
import threading
import time
import logging
import base58
import requests
import websockets.sync.client

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
        self._session: Optional[requests.sessions.Session] = None
        self._headers = {
            'Content-Type': 'application/json'
        }

    def _send_post_request_impl(self, request: Union[List[Dict[str, Any]], Dict[str, Any]]) -> requests.Response:

        if self._session is None:
            self._session = requests.sessions.Session()

        try:
            raw_response = self._session.post(self._endpoint_uri, headers=self._headers, json=request)
            raw_response.raise_for_status()

            return raw_response

        except (BaseException, ):
            self._session = None
            raise

    def _send_post_request(self, request: Union[List[Dict[str, Any]], Dict[str, Any]]) -> requests.Response:
        """This method is used to make retries to send request to Solana"""

        def _clean_solana_err(exc: BaseException) -> str:
            return str(exc).replace(self._endpoint_uri, 'XXXXX')

        for retry in itertools.count():
            try:
                return self._send_post_request_impl(request)

            except requests.exceptions.RequestException as exc:
                if retry > 1:
                    str_err = _clean_solana_err(exc)
                    LOG.debug(
                        f'Receive connection error {str_err} on connection to Solana. '
                        f'Attempt {retry + 1} to send the request to Solana node...'
                    )

                time.sleep(1)

            except BaseException as exc:
                str_err = _clean_solana_err(exc)
                LOG.error(f'Unknown exception on send request to Solana: {str_err}')
                raise SolanaUnavailableError(str_err)

    def _build_rpc_request(self, method: str, *param_list: Any) -> Dict[str, Any]:
        request_id = next(self._request_cnt) + 1
        if request_id >= 100_000:
            self._request_cnt = itertools.count()

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

    def _send_rpc_batch_request(self, method: str, params_list: List[Any]) -> List[RPCResponse]:
        request_cnt = len(params_list)
        request_size = 0
        full_response_list = list()
        request_list = list()

        for params in params_list:
            request = self._build_rpc_request(method, *params)
            request_list.append(request)

            request_cnt -= 1
            request_size += len(json.dumps(request)) + 2

            # Protection from big payload
            if request_size >= 48 * 1024 or request_cnt == 0:
                raw_response = self._send_post_request(request_list)
                response_list = cast(List[RPCResponse], raw_response.json())
                full_response_list += response_list

                request_list = list()
                request_size = 0

        full_response_list.sort(key=lambda r: r['id'])

        # for request, response in itertools.zip_longest(full_request_list, full_response_list):
        #     LOG.debug(f'Request: {request}')
        #     LOG.debug(f'Response: {response}')
        #     if request['id'] != response['id']:
        #         raise RuntimeError(f'Invalid RPC response: request {request} response {response}')

        return full_response_list

    def is_healthy(self) -> Optional[bool]:
        """Ask Solana node about the status.
        The method should return immediately without attempts to repeat the request."""
        request = self._build_rpc_request('getHealth', )

        try:
            raw_response = self._send_post_request_impl(request)
            json_response = cast(RPCResponse, raw_response.json())
            status = json_response.get('result', 'bad')
            return status == 'ok'

        except (BaseException, ):
            return None

    def get_cluster_nodes(self) -> List[Dict[str, Any]]:
        return self._send_rpc_request('getClusterNodes').get('result', list())

    def get_solana_version(self) -> str:
        return self._send_rpc_request('getVersion').get('result', dict()).get('solana-core', 'Unknown')

    def get_slots_behind(self) -> Optional[int]:
        response = self._send_rpc_request('getHealth')
        status = response.get('result', None)
        if status == 'ok':
            return 0

        slots_behind = SolTxErrorParser(self._config.evm_program_id, response).get_slots_behind()
        if slots_behind is not None:
            return int(slots_behind)
        return None

    def get_sig_list_for_address(self, address: Union[str, SolPubKey], before: Optional[str], limit: int,
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

    def get_finalized_slot(self) -> int:
        return self.get_block_slot(SolCommit.Finalized)

    def get_confirmed_slot(self) -> int:
        return self.get_block_slot(SolCommit.Confirmed)

    @staticmethod
    def _decode_account_info(address: Union[str, SolPubKey], raw_account: Dict[str, Any]) -> AccountInfo:
        data = base64.b64decode(raw_account.get('data', None)[0])
        account_tag = data[0] if len(data) > 0 else 0
        lamports = raw_account.get('lamports', 0)
        owner = SolPubKey.from_string(raw_account.get('owner', None))
        if isinstance(address, str):
            address = SolPubKey.from_string(address)
        return AccountInfo(address, account_tag, lamports, owner, data)

    def get_account_info(self, pubkey: Union[str, SolPubKey], length: Optional[int] = None,
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
            # LOG.debug(f"Can't get information about {str(pubkey)}")
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
                    account_info_list.append(self._decode_account_info(pubkey, info))
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

    def get_state_tx_cnt(self, neon_account: Union[str, bytes, NeonAddress, NeonAccountInfo, None],
                         commitment=SolCommit.Confirmed) -> int:
        if (neon_account is None) or isinstance(neon_account, NeonAccountInfo):
            neon_account_info = neon_account
        else:
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
            parent_block_slot=net_block.get('parentSlot', None),
            tx_receipt_list=net_block.get('transactions', list())
        )

    def get_first_available_slot(self) -> int:
        response = self._send_rpc_request('getFirstAvailableBlock')
        slot = response.get('result', 0)
        LOG.debug(f"Solana's first slot {slot}")
        if slot > 0:
            slot += 512

        while self.get_block_info(slot).is_empty():
            LOG.debug(f'Skip block {slot}...')
            slot += 1

        return slot

    @staticmethod
    def _get_block_info_opts(commitment=SolCommit.Confirmed, full=False) -> Dict[str, Any]:
        return dict(
            commitment=SolCommit.to_solana(commitment),
            encoding='json',
            transactionDetails=('full' if full else 'none'),
            maxSupportedTransactionVersion=0,
            rewards=False
        )

    def get_block_info(self, block_slot: int, commitment=SolCommit.Confirmed, full=False) -> SolBlockInfo:
        opts = self._get_block_info_opts(commitment, full)

        response = self._send_rpc_request('getBlock', block_slot, opts)
        net_block = response.get('result', None)
        if not net_block:
            return SolBlockInfo(block_slot=block_slot)

        return self._decode_block_info(block_slot, net_block)

    def get_block_info_list(self, block_slot_list: List[int],
                            commitment=SolCommit.Confirmed, full=False) -> List[SolBlockInfo]:
        block_list = list()
        if len(block_slot_list) == 0:
            return block_list

        opts = self._get_block_info_opts(commitment, full)
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
            if isinstance(raw_result, str):
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
                                     commitment: SolCommit.Type,
                                     timeout_sec: float) -> bool:
        if not tx_sig_list:
            return True

        is_done = False
        with websockets.sync.client.connect(self._config.solana_websocket_url) as websocket:
            for tx_sig in tx_sig_list:
                request = self._build_rpc_request('signatureSubscribe', tx_sig, {
                    'commitment': commitment
                })
                websocket.send(json.dumps(request))

            timeout_timer = threading.Timer(timeout_sec, lambda: websocket.close())
            timeout_timer.start()

            sub_set: Set[int, bool] = set()
            for response in websocket:
                response = json.loads(response)

                if response.get('method', '') == 'signatureNotification':
                    sub_id = response.get('params', dict()).get('subscription', None)
                    if sub_id is not None:
                        sub_set.add(sub_id)

                if len(tx_sig_list) == len(sub_set):
                    is_done = True
                    websocket.close()
                    break

            timeout_timer.cancel()
            timeout_timer.join()

        return is_done

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
