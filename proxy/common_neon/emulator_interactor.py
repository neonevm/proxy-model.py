import json
import logging

from typing import Optional, Dict, Any
from .errors import EthereumError
from ..environment import neon_cli

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def call_emulated(contract_id, caller_id, data=None, value=None):
    output = emulator(contract_id, caller_id, data, value)
    logger.debug(f"Call emulated. contract_id: {contract_id}, caller_id: {caller_id}, data: {data}, value: {value}, return: {output}")
    result = json.loads(output)
    check_emulated_exit_status(result)
    return result


def check_emulated_exit_status(result: Dict[str, Any]):
    exit_status = result['exit_status']
    if exit_status == 'revert':
        result_value = decode_revert_message(result['result'])
        if result_value is None:
            raise EthereumError(code=3, message='execution reverted')
        else:
            raise EthereumError(code=3, message='execution reverted: ' + result_value, data='0x' + result_value)

    if result["exit_status"] != "succeed":
        raise Exception("evm emulator error ", result)


def decode_revert_message(data) -> Optional[str]:
    if len(data) == 0:
        logger.debug(f"Empty reverting signature: {len(data)}, data: 0x{data.hex()}")
        return None

    if len(data) < 8:
        raise Exception(f"To less bytes to decode reverting signature: {len(data)}, data: 0x{data.hex()}")

    if data[:8] != '08c379a0':
        logger.debug(f"Failed to decode revert_message, unknown revert signature: {data[:8]}")
        return None

    if len(data) < 8 + 64:
        raise Exception(f"Too less bytes to decode revert msg offset: {len(data)}, data: 0x{data.hex()}")
    offset = int(data[8:8 + 64], 16)

    if len(data) < 8 + offset * 2 + 64:
        raise Exception(f"Too less bytes to decode revert msg len: {len(data)}, data: 0x{data.hex()}")
    length = int(data[8 + offset * 2:8 + offset * 2 + 64], 16)

    if len(data) < 8 + offset * 2 + 64 + length * 2:
        raise Exception(f"Too less bytes to decode revert msg: {len(data)}, data: 0x{data.hex()}")

    message = str(bytes.fromhex(data[8 + offset * 2 + 64:8 + offset * 2 + 64 + length * 2]), 'utf8')
    return message


def emulator(contract, sender, data, value):
    data = data or "none"
    value = value or ""
    return neon_cli().call("emulate", sender, contract, data, value)
