from typing import Optional, Dict, Any

import logging
import requests

from ..common_neon.config import Config
from ..common_neon.data import NeonEmulatorResult, NeonEmulatorExitStatus
from ..common_neon.elf_params import ElfParams
from ..common_neon.errors import EthereumError
from ..common_neon.utils.eth_proto import NeonTx


LOG = logging.getLogger(__name__)
RPCRequest = Dict[str, Any]
RPCResponse = Dict[str, Any]


class _NeonCoreApiClient:
    def __init__(self, port: int):
        self._port = port
        self._client_impl: Optional[requests.Session] = None

        base_url = f'http://127.0.0.1:{port}/api'
        self._emulate_url = base_url + '/emulate'
        self._get_storage_at_url = base_url + '/get-storage-at'
        self._get_neon_account_url = base_url + '/get-ether-account-data'

        self._headers = {
            'Content-Type': 'application/json',
        }

    def __del__(self):
        self._close()

    @property
    def port(self) -> int:
        return self._port

    @property
    def _client(self) -> requests.Session:
        if self._client_impl is not None:
            return self._client_impl

        self._client_impl = requests.Session()
        self._client_impl.headers.update(self._headers)
        return self._client_impl

    def _close(self) -> None:
        if self._client_impl is None:
            return
        self._client_impl.close()
        self._client_impl = None

    def emulate(self, request: RPCRequest) -> NeonEmulatorResult:
        response = self._post(self._emulate_url, request)
        return NeonEmulatorResult(response.get('value'))

    def _post(self, url: str, request: RPCRequest) -> RPCResponse:
        raw_response: Optional[requests.Response] = None
        try:
            raw_response = self._client.post(url, json=request)
            raw_response.raise_for_status()
            return raw_response.json()
        except (BaseException,):
            self._close()
            if raw_response is not None:
                raise ValueError(raw_response.content)
            raise


class NeonCoreApiClient:
    def __init__(self, config: Config):
        self._config = config
        self._retry_cnt = len(config.solana_url_list)

        port = config.neon_core_api_port
        self._client_list = [_NeonCoreApiClient(port + idx) for idx in range(self._retry_cnt)]
        self._last_client_idx = 0

    def _get_client(self) -> _NeonCoreApiClient:
        idx = self._last_client_idx

        self._last_client_idx += 1
        if self._last_client_idx >= len(self._client_list):
            self._last_client_idx = 0

        return self._client_list[idx]

    def _call(self, method, *args, **kwargs) -> Any:
        for retry in range(self._retry_cnt):
            client = self._get_client()
            try:
                return method(client, *args, **kwargs)
            except BaseException as exc:
                LOG.warning(f'Fail to call {method.__name__} on the neon_core_api({client.port})', exc_info=exc)

    def emulate(
        self,
        contract: str,
        sender: str,
        data: Optional[str],
        value: Optional[str],
        check_result=False
    ) -> NeonEmulatorResult:
        if not sender:
            sender = '0x0000000000000000000000000000000000000000'

        if data is not None:
            if data[:2] in {'0x', '0X'}:
                data = data[2:]
            data = list(bytes.fromhex(data))

        if not value:
            value = '0x0'

        request = dict(
            token_mint=str(ElfParams().neon_token_mint),
            chain_id=ElfParams().chain_id,
            max_steps_to_execute=self._config.max_evm_step_cnt_emulate,
            cached_accounts=None,
            solana_accouts=None,
            sender=sender,
            contract=contract,
            value=value,
            data=data,
            gas_limit=None
        )

        result = self._call(_NeonCoreApiClient.emulate, request)
        if result is None:
            raise EthereumError(message='Fail to execute emulation')
        if check_result:
            self._check_exit_status(result)

        return result

    def emulate_neon_tx(self, neon_tx: NeonTx) -> NeonEmulatorResult:
        return self.emulate(neon_tx.hex_to_address, neon_tx.hex_sender, neon_tx.hex_call_data, hex(neon_tx.value))

    def _check_exit_status(self, result: NeonEmulatorResult):
        exit_status = result.exit_status
        if exit_status == NeonEmulatorExitStatus.Revert:
            revert_data = result.revert_data
            LOG.debug(f'Got revert call emulated result with data: {revert_data}')
            result_value = self._decode_revert_message(revert_data)
            if result_value is None:
                raise EthereumError(code=3, message='execution reverted', data='0x' + revert_data)
            else:
                raise EthereumError(code=3, message='execution reverted: ' + result_value, data='0x' + revert_data)

        if exit_status != NeonEmulatorExitStatus.Succeed:
            LOG.debug(f"Got not succeed emulate exit_status: {exit_status}")
            reason = result.exit_reason
            if isinstance(reason, str):
                raise EthereumError(code=3, message=f'execution finished with error: {reason}')
            raise EthereumError(code=3, message=exit_status)

    @staticmethod
    def _decode_revert_message(data: str) -> Optional[str]:
        data_len = len(data)
        if data_len == 0:
            return None

        if data_len < 8:
            raise Exception(f'Too less bytes to decode revert signature: {data_len}, data: 0x{data}')

        if data[:8] == '4e487b71':  # keccak256("Panic(uint256)")
            return None

        if data[:8] != '08c379a0':  # keccak256("Error(string)")
            LOG.debug(f'Failed to decode revert_message, unknown revert signature: {data[:8]}')
            return None

        if data_len < 8 + 64:
            raise Exception(f'Too less bytes to decode revert msg offset: {data_len}, data: 0x{data}')
        offset = int(data[8:8 + 64], 16) * 2

        if data_len < 8 + offset + 64:
            raise Exception(f'Too less bytes to decode revert msg len: {data_len}, data: 0x{data}')
        length = int(data[8 + offset:8 + offset + 64], 16) * 2

        if data_len < 8 + offset + 64 + length:
            raise Exception(f'Too less bytes to decode revert msg: {data_len}, data: 0x{data}')

        message = str(bytes.fromhex(data[8 + offset + 64:8 + offset + 64 + length]), 'utf8')
        return message
