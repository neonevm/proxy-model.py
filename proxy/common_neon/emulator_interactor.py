import json
import logging

from .errors import EthereumError
from ..environment import neon_cli

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def call_emulated(contract_id, caller_id, data=None, value=None):
    output = emulator(contract_id, caller_id, data, value)
    logger.debug(f"Call emulated. contract_id: {contract_id}, caller_id: {caller_id}, data: {data}, value: {value}, return: {output}")
    result = json.loads(output)
    exit_status = result['exit_status']
    if exit_status == 'revert':
        result_value = result['result']
        raise_eth_err_by_revert(result_value)

    if result["exit_status"] != "succeed":
        raise Exception("evm emulator error ", result)
    return result


def raise_eth_err_by_revert(result_value: str):
    if len(result_value) < 8 or result_value[:8] != '08c379a0':
        raise EthereumError(code=3, message='execution reverted')

    offset = int(result_value[8:8 + 64], 16)
    length = int(result_value[8 + 64:8 + 64 + 64], 16)
    message = str(bytes.fromhex(result_value[8 + offset * 2 + 64:8 + offset * 2 + 64 + length * 2]), 'utf8')
    raise EthereumError(code=3, message=message, data='0x' + result_value)


def emulator(contract, sender, data, value):
    data = data or "none"
    value = value or ""
    return neon_cli().call("emulate", sender, contract, data, value)
