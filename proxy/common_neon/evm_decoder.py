# File: proxy/common_neon/evm_decoder.py
# Module: evm_decoder
# Description: contains decoders from binary logs

import re
import base64
from typing import Any, Dict, Iterable, List
from dataclasses import dataclass, field
from .environment_data import EVM_LOADER_ID
from .utils import NeonTxResultInfo

@dataclass
class ReturnDTO:
    exit_status: int = 0
    gas_used: int = 0
    return_value: bytes = None


def unpack_return(data: Iterable[str]) -> ReturnDTO:
    '''Unpacks base64-encoded return data'''
    exit_status = 0
    gas_used = 0
    return_value = b''
    for i, s in enumerate(data):
        bs = base64.b64decode(s)
        if i == 0:
            exit_status = int.from_bytes(bs, "little")
            exit_status = 0x1 if exit_status < 0xd0 else 0x0
        elif i == 1:
            gas_used = int.from_bytes(bs, "little")
        elif i == 2:
            return_value = bs
    return ReturnDTO(exit_status, gas_used, return_value)


@dataclass
class EventDTO:
    address: bytes = None
    count_topics: int = 0
    topics: List[bytes] = None
    log_data: bytes = None


def unpack_event_log(data: Iterable[str]) -> EventDTO:
    '''Unpacks base64-encoded event data'''
    address = b''
    count_topics = 0
    t = []
    log_data = b''
    for i, s in enumerate(data):
        bs = base64.b64decode(s)
        if i == 0:
            address = bs
        elif i == 1:
            count_topics = int.from_bytes(bs, 'little')
        elif 1 < i < 6:
            if count_topics > (i - 2):
                t.append(bs)
            else:
                log_data = bs
        else:
            log_data = bs
    return EventDTO(address, count_topics, t, log_data)


@dataclass
class LogIxDTO:
    return_dto: ReturnDTO = None
    event_dtos: List[EventDTO] = field(default_factory=list)

    def empty(self) -> bool:
        return self.return_dto is None


def process_logs(logs: List[str]) -> List[LogIxDTO]:
    '''Reads log messages from a transaction receipt. Parses each line to rebuild sequence of Neon instructions. Extracts return and events information from these lines.'''
    program_invoke = re.compile(r'^Program (\w+) invoke \[(\d+)\]')
    program_success = re.compile(r'^Program (\w+) success')
    program_failed = re.compile(r'^Program (\w+) failed')
    program_data = re.compile(r'^Program data: (.+)$')
    tx_list: List[LogIxDTO] = []

    for line in logs:
        m = program_invoke.match(line)
        if m:
            program_id = m.group(1)
            if program_id == EVM_LOADER_ID:
                tx_list.append(LogIxDTO())
        m = program_success.match(line)
        if m:
            program_id = m.group(1) # do nothing
        m = program_failed.match(line)
        if m:
            program_id = m.group(1)
            if program_id == EVM_LOADER_ID:
                tx_list.pop(-1)  # remove failed invocation
        m = program_data.match(line)
        if m:
            tail = m.group(1)
            data = re.findall("\S+", tail)
            mnemonic = base64.b64decode(data[0]).decode('utf-8')
            if mnemonic == "RETURN":
                tx_list[-1].return_dto = unpack_return(data[1:])
            elif mnemonic.startswith("LOG"):
                tx_list[-1].event_dtos.append(unpack_event_log(data[1:]))
            else:
                assert False, f'Wrong mnemonic {mnemonic}'

    return tx_list


def decode(info: NeonTxResultInfo, neon_sign: str, tx: Dict[Any, Any], ix_idx=-1) -> NeonTxResultInfo:
    '''Extracts Neon transaction result information'''
    log = process_logs(tx['meta']['logMessages'])

    if ix_idx < 0:
        ix_idx = 0

    if ix_idx >= 0:
        log_ix = log[ix_idx]

        if log_ix.return_dto is not None:
            if info.slot != -1:
                info.warning(f'NeonTxResultInfo already loaded')
            info.gas_used = hex(log_ix.return_dto.gas_used)
            info.status = hex(log_ix.return_dto.exit_status)
            info.return_value = log_ix.return_dto.return_value.hex()
            info.sol_sign = tx['transaction']['signatures'][0]
            info.slot = tx['slot']
            info.idx = ix_idx

        log_idx = len(info.logs)
        for e in log_ix.event_dtos:
            topics = []
            for i in range(e.count_topics):
                topics.append('0x' + e.topics[i].hex())
            rec = {
                'address': '0x' + e.address.hex(),
                'topics': topics,
                'data': '0x' + e.log_data.hex(),
                'transactionLogIndex': hex(log_idx),
                'transactionIndex': hex(info.idx),
                'logIndex': hex(log_idx),
                'transactionHash': neon_sign,
                # 'blockNumber': block_number, # set when transaction found
                # 'blockHash': block_hash # set when transaction found
            }
            info.logs.append(rec)

        if len(info.logs) > 0:
            assert info.slot != -1, 'Events without result'

    return info
