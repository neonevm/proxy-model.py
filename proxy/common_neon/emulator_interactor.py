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
        message = 'execution reverted: ' + result_value if result_value is not None else 'execution reverted'
        raise EthereumError(code=3, message=message, data='0x' + result_value)

    if result["exit_status"] != "succeed":
        raise Exception("evm emulator error ", result)


def decode_revert_message(data) -> Optional[str]:
    if len(data) < 8 or data[:8] != '08c379a0':
        return None
    offset = int(data[8:8 + 64], 16)
    length = int(data[8 + 64:8 + 64 + 64], 16)
    message = str(bytes.fromhex(data[8 + offset * 2 + 64:8 + offset * 2 + 64 + length * 2]), 'utf8')
    return message


def raise_eth_err_by_revert(result_value: str):
    if len(result_value) < 8 or result_value[:8] != '08c379a0':
        raise EthereumError(code=3, message='execution reverted')


    raise EthereumError(code=3, message='execution reverted: ' + message, data='0x' + result_value)


def emulator(contract, sender, data, value):
    data = data or "none"
    value = value or ""
    return neon_cli().call("emulate", sender, contract, data, value)
