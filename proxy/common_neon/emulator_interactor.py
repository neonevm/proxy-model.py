import logging
import re
import subprocess

from typing import Optional

from .config import Config
from .data import NeonEmulatorResult, NeonEmulatorExitStatus
from .elf_params import ElfParams
from .environment_utils import NeonCli
from .errors import EthereumError, NoMoreRetriesError
from .utils import str_fmt_object
from .utils.eth_proto import NeonTx


LOG = logging.getLogger(__name__)


def call_tx_emulator(config: Config, neon_tx: NeonTx) -> NeonEmulatorResult:
    sender = neon_tx.hex_sender
    contract = neon_tx.hex_contract
    dst = 'deploy' if contract else neon_tx.hex_to_address
    return call_emulator(config, dst, sender, neon_tx.hex_call_data, hex(neon_tx.value))


def check_emulator_exit_status(result: NeonEmulatorResult):
    exit_status = result.exit_status
    if exit_status == NeonEmulatorExitStatus.Revert:
        revert_data = result.revert_data
        LOG.debug(f"Got revert call emulated result with data: {revert_data}")
        result_value = decode_revert_message(revert_data)
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
    _re = re.compile(r'EVM Error. Insufficient balance for transfer, account = 0x([0-9a-fA-F]+), required = (\d+)')

    def execute(self, msg: str) -> str:
        match = self._re.match(msg)
        if match is None:
            return msg
        sender = match.group(1)
        amount = match.group(2)
        return f'insufficient funds for transfer: address {sender} want {amount}'


def convert_evm_error(msg: str) -> str:
    return ConvertEVMInsufficientBalanceParser().execute(msg)


def call_emulator(config: Config,
                  contract: str, sender: str,
                  data: Optional[str], value: Optional[str]) -> NeonEmulatorResult:
    LOG.debug(f'{str_fmt_object(dict(contract=contract, caller=sender, data=data, value=value), name="Call")}')

    value = value or ""
    neon_token_mint = ElfParams().neon_token_mint
    chain_id = ElfParams().chain_id
    max_evm_steps_to_execute = config.max_evm_step_cnt_emulate
    if data is not None:
        if not data.startswith("0x"):
            data = "0x" + data
        data = {"data": data}
    try:
        res_dict = NeonCli(config, True).call(
            'emulate',
            '--token_mint', str(neon_token_mint),
            '--chain_id', str(chain_id),
            '--max_steps_to_execute', str(max_evm_steps_to_execute),
            sender,
            contract,
            value,
            data=data
        )
        LOG.debug(f'return: {res_dict}')
        return NeonEmulatorResult(res_dict)

    except subprocess.TimeoutExpired:
        raise NoMoreRetriesError()

    except subprocess.CalledProcessError as err:
        msg = convert_evm_error(str(err.stderr))
        raise EthereumError(message=msg)
