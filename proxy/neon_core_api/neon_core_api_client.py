import logging
import requests

from typing import Optional, Dict, Any, Union, List, Tuple

from ..common_neon.address import NeonAddress
from ..common_neon.config import Config
from ..common_neon.data import NeonEmulatorResult, NeonEmulatorExitStatus
from ..common_neon.elf_params import ElfParams
from ..common_neon.errors import EthereumError
from ..common_neon.utils.utils import cached_property
from ..common_neon.utils.eth_proto import NeonTx
from ..common_neon.solana_block import SolBlockInfo
from ..common_neon.solana_tx import SolCommit

from .neon_layouts import NeonAccountInfo
from .neon_cli import NeonCli


LOG = logging.getLogger(__name__)
RPCRequest = Dict[str, Any]
RPCResponse = Dict[str, Any]


class _NeonCoreApiClient:
    def __init__(self, port: int):
        self._port = port

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

    @cached_property
    def _client(self) -> requests.Session:
        client = requests.Session()
        client.headers.update(self._headers)
        return client

    def _close(self) -> None:
        self._client.close()

    def emulate(self, request: RPCRequest) -> NeonEmulatorResult:
        response = self._post(self._emulate_url, request)
        return NeonEmulatorResult(response.get('value'))

    def get_storage_at(self, request: RPCRequest) -> Optional[str]:
        response = self._get(self._get_storage_at_url, request)
        value = response.get('value', None)
        return bytes(value).hex() if value else None

    def get_neon_account_info(self, request: RPCRequest) -> Optional[NeonAccountInfo]:
        response = self._get(self._get_neon_account_url, request)
        json_acct = response.get('value')
        return NeonAccountInfo.from_json(json_acct) if json_acct else None

    def _post(self, url: str, request: RPCRequest) -> RPCResponse:
        return self._send_request(lambda: self._client.post(url, json=request))

    def _get(self, url: str, request: RPCRequest) -> RPCResponse:
        return self._send_request(lambda: self._client.get(url, params=request))

    def _send_request(self, request) -> RPCResponse:
        raw_response: Optional[requests.Response] = None
        try:
            raw_response = request()
            # TODO: strange workflow in neon-core-api
            # raw_response.raise_for_status()
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
        value: Optional[Union[str, int]],
        block: Optional[SolBlockInfo] = None,
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
        elif isinstance(value, int):
            value = hex(value)

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

        request = self._add_block(request, block)

        result = self._call(_NeonCoreApiClient.emulate, request)
        if result is None:
            raise EthereumError(message='Fail to execute emulation')
        if check_result:
            self._check_exit_status(result)

        return result

    def emulate_neon_tx(self, neon_tx: NeonTx) -> NeonEmulatorResult:
        return self.emulate(neon_tx.hex_to_address, neon_tx.hex_sender, neon_tx.hex_call_data, neon_tx.value)

    def get_storage_at(self, contract: str, position: str, block: SolBlockInfo) -> str:
        request = dict(
            contract_id=contract,
            index=position
        )
        request = self._add_block(request, block)
        value = self._call(_NeonCoreApiClient.get_storage_at, request)
        assert value is not None
        return '0x' + value

    def get_neon_account_info(
        self,
        addr: Union[str, bytes, NeonAddress],
        block: Optional[SolBlockInfo] = None
    ) -> Optional[NeonAccountInfo]:
        if isinstance(addr, bytes):
            addr = NeonAddress(addr)
        if isinstance(addr, NeonAddress):
            addr = str(addr)

        request = self._add_block(dict(ether=addr), block)
        return self._call(_NeonCoreApiClient.get_neon_account_info, request)

    def get_neon_account_info_list(
        self,
        addr_list: List[Union[str, bytes, NeonAddress]],
        block: Optional[SolBlockInfo] = None
    ) -> List[NeonAccountInfo]:
        return [self.get_neon_account_info(addr, block) for addr in addr_list]

    def get_state_tx_cnt(
        self,
        acct: Union[str, bytes, NeonAddress, NeonAccountInfo, None],
        block: Optional[SolBlockInfo] = None
    ) -> int:
        if (not acct) or isinstance(acct, NeonAccountInfo):
            neon_acct_info = acct
        else:
            neon_acct_info = self.get_neon_account_info(acct, block)

        return neon_acct_info.tx_count if neon_acct_info is not None else 0

    def read_elf_params(self, last_deployed_slot: int) -> Tuple[int, Dict[str, str]]:
        return NeonCli(self._config, False).read_elf_params(last_deployed_slot)

    def version(self) -> str:
        return NeonCli(self._config, False).version()

    def _add_block(self, request: RPCRequest, block: Optional[SolBlockInfo]) -> RPCRequest:
        if not block:
            pass
        elif block.sol_commit in {SolCommit.Confirmed, SolCommit.Processed}:
            pass
        elif len(self._config.ch_dsn_list):
            request.update(dict(slot=block.block_slot))
        else:
            request.update(dict(commitment=block.sol_commit))
        return request

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
