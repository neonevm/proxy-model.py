import re
import subprocess
import logging
from typing import Optional, Dict, Any

from ..common_neon.data import NeonEmulatedResult
from ..common_neon.environment_utils import NeonCli
from ..common_neon.errors import EthereumError, NoMoreRetriesError
from ..common_neon.config import Config
from ..common_neon.elf_params import ElfParams
from ..common_neon.eth_proto import NeonTx
from ..common_neon.utils import str_fmt_object


LOG = logging.getLogger(__name__)


def call_emulated(config: Config, contract_id, caller_id, data=None, value=None) -> NeonEmulatedResult:
    LOG.debug(f'{str_fmt_object(dict(contract=contract_id, caller=caller_id, data=data, value=value), name="Call")}')
    output = emulator(config, contract_id, caller_id, data, value)
    LOG.debug(f'return: {output}')
    return output


def call_tx_emulated(config: Config, neon_tx: NeonTx) -> NeonEmulatedResult:
    sender = neon_tx.hex_sender
    contract = neon_tx.hex_contract
    dst = 'deploy' if contract else neon_tx.hex_to_address
    return call_emulated(config, dst, sender, neon_tx.hex_call_data, hex(neon_tx.value))


def check_emulated_exit_status(result: Dict[str, Any]):
    exit_status = result['exit_status']
    if exit_status == 'revert':
        revert_data = result.get('result')
        LOG.debug(f"Got revert call emulated result with data: {revert_data}")
        result_value = decode_revert_message(revert_data)
        if result_value is None:
            raise EthereumError(code=3, message='execution reverted', data='0x' + revert_data)
        else:
            raise EthereumError(code=3, message='execution reverted: ' + result_value, data='0x' + revert_data)

    if exit_status != "succeed":
        LOG.debug(f"Got not succeed emulate exit_status: {exit_status}")
        reason = result.get('exit_reason')
        if isinstance(reason, str):
            raise EthereumError(code=3, message=f'execution finished with error: {reason}')
        raise EthereumError(code=3, message=exit_status)


def decode_revert_message(data: str) -> Optional[str]:
    data_len = len(data)
    if data_len == 0:
        return None

    if data_len < 8:
        raise Exception(f"Too less bytes to decode revert signature: {data_len}, data: 0x{data}")

    if data[:8] == '4e487b71':  # keccak256("Panic(uint256)")
        return None

    if data[:8] != '08c379a0':  # keccak256("Error(string)")
        LOG.debug(f"Failed to decode revert_message, unknown revert signature: {data[:8]}")
        return None

    if data_len < 8 + 64:
        raise Exception(f"Too less bytes to decode revert msg offset: {data_len}, data: 0x{data}")
    offset = int(data[8:8 + 64], 16) * 2

    if data_len < 8 + offset + 64:
        raise Exception(f"Too less bytes to decode revert msg len: {data_len}, data: 0x{data}")
    length = int(data[8 + offset:8 + offset + 64], 16) * 2

    if data_len < 8 + offset + 64 + length:
        raise Exception(f"Too less bytes to decode revert msg: {data_len}, data: 0x{data}")

    message = str(bytes.fromhex(data[8 + offset + 64:8 + offset + 64 + length]), 'utf8')
    return message


class ConvertEVMInsufficientBalanceParser:
    _re = re.compile('EVM Error. Insufficient balance for transfer, account = 0x([0-9a-fA-F]+), required = (\d+)')

    def execute(self, msg: str) -> str:
        match = self._re.match(msg)
        if match is None:
            return msg
        sender = match.group(1)
        amount = match.group(2)
        return f'insufficient funds for transfer: address {sender} want {amount}'


def convert_evm_error(msg: str) -> str:
    return ConvertEVMInsufficientBalanceParser().execute(msg)


def emulator(config: Config, contract: str, sender: str, data: Optional[str], value: Optional[str]):
    value = value or ""
    neon_token_mint = ElfParams().neon_token_mint
    chain_id = ElfParams().chain_id
    max_evm_steps_to_execute = config.max_evm_step_cnt_emulate
    try:
        return NeonCli(config).call(
            'emulate',
            '--token_mint', str(neon_token_mint),
            '--chain_id', str(chain_id),
            '--max_steps_to_execute', str(max_evm_steps_to_execute),
            sender,
            contract,
            value,
            data=data
        )

    except subprocess.TimeoutExpired:
        raise NoMoreRetriesError()

    except subprocess.CalledProcessError as err:
        msg = convert_evm_error(str(err.stderr))
        raise EthereumError(message=msg)

