import base64
import re

from dataclasses import dataclass
from typing import List, Iterator, Optional, Tuple

from logged_groups import logged_group

from ..common_neon.environment_data import EVM_LOADER_ID


@dataclass(frozen=True)
class NeonLogTxReturn:
    gas_used: int
    status: int
    return_value: bytes


@dataclass(frozen=True)
class NeonLogTxCancel:
    gas_used: int


@dataclass(frozen=True)
class NeonLogTxIx:
    gas_used: int


@dataclass(frozen=True)
class NeonLogTxEvent:
    address: bytes
    topic_list: List[bytes]
    data: bytes


@dataclass(frozen=True)
class NeonLogTxSig:
    neon_sig: bytes


@dataclass(frozen=True)
class SolLogBPFCycleUsage:
    max_bpf_cycle_cnt: int
    used_bpf_cycle_cnt: int


@dataclass(frozen=True)
class SolLogHeapUsage:
    heap_size: int


@dataclass(frozen=True)
class NeonLogInfo:
    sol_bpf_cycle_usage: Optional[SolLogBPFCycleUsage]
    sol_heap_usage: Optional[SolLogHeapUsage]

    neon_tx_sig: Optional[NeonLogTxSig]
    neon_tx_ix: Optional[NeonLogTxIx]
    neon_tx_return: Optional[NeonLogTxReturn]
    neon_tx_event_list: List[NeonLogTxEvent]


@logged_group('neon.decoder')
class _NeonLogDecoder:
    _re_data = re.compile(r'^Program data: (.+)$')
    _bpf_cycle_cnt_re = re.compile(f'^Program {EVM_LOADER_ID}' + r' consumed (\d+) of (\d+) compute units$')
    _heap_size_re = re.compile(r'^Program log: Total memory occupied: (\d+)$')

    def _decode_bpf_cycle_usage(self, line: str) -> Optional[SolLogBPFCycleUsage]:
        match = self._bpf_cycle_cnt_re.match(line)
        if match is None:
            return None

        return SolLogBPFCycleUsage(used_bpf_cycle_cnt=int(match[1]), max_bpf_cycle_cnt=int(match[2]))

    def _decode_heap_usage(self, line: str) -> Optional[SolLogHeapUsage]:
        match = self._heap_size_re.match(line)
        if match is None:
            return None

        return SolLogHeapUsage(heap_size=int(match[1]))

    def _decode_mnemonic(self, line: str) -> Tuple[str, List[str]]:
        match = self._re_data.match(line)
        if match is None:
            return '', []

        tail: str = match.group(1)
        data_list: List[str] = tail.split()
        if len(data_list) < 2:
            return '', []

        mnemonic = base64.b64decode(data_list[0]).decode('utf-8')
        return mnemonic, data_list[1:]

    def _decode_neon_tx_return(self, data_list: List[str]) -> Optional[NeonLogTxReturn]:
        """Unpacks base64-encoded return data"""
        if len(data_list) < 2:
            self.error(f'Failed to decode return data: less then 2 elements in {data_list}')
            return None

        bs = base64.b64decode(data_list[0])
        exit_status = int.from_bytes(bs, "little")
        exit_status = 0x1 if exit_status < 0xd0 else 0x0

        bs = base64.b64decode(data_list[1])
        gas_used = int.from_bytes(bs, "little")

        return_value = base64.b64decode(data_list[2]) if len(data_list) > 2 else b''

        return NeonLogTxReturn(gas_used=gas_used, status=exit_status, return_value=return_value)

    def _decode_neon_tx_event(self, data_list: List[str]) -> Optional[NeonLogTxEvent]:
        """Unpacks base64-encoded event data"""
        if len(data_list) < 3:
            self.error(f'Failed to decode events data: less then 3 elements in {data_list}')
            return None

        bs = base64.b64decode(data_list[1])
        topic_cnt = int.from_bytes(bs, 'little')
        if topic_cnt > 4:
            self.error(f'Failed to decode events data: count of topics more than 4 = {topic_cnt}')
            return None

        address = base64.b64decode(data_list[0])
        topic_list = [base64.b64decode(data_list[2 + i]) for i in range(topic_cnt)]

        data_index = 2 + topic_cnt
        data = base64.b64decode(data_list[data_index]) if data_index < len(data_list) else b''

        return NeonLogTxEvent(address=address, topic_list=topic_list, data=data)

    def _decode_neon_tx_sig(self, data_list: List[str]) -> Optional[NeonLogTxSig]:
        """Extracts Neon transaction hash"""
        if len(data_list) != 1:
            self.error(f'Failed to decode neon tx hash: should be 1 element in {data_list}')
            return None

        tx_sig = base64.b64decode(data_list[0])
        if len(tx_sig) != 32:
            self.error(f'Failed to decode neon tx hash: wrong hash length in {data_list}')
            return None

        return NeonLogTxSig(neon_sig=tx_sig)

    def _decode_neon_tx_cancel(self, data_list: List[str]) -> Optional[NeonLogTxReturn]:
        """Extracts gas_used of the canceled transaction"""

        if len(data_list) != 1:
            self.error(f'Failed to decode neon tx cancel: should be 1 element in {data_list}')
            return None

        bs = base64.b64decode(data_list[0])
        gas_used = int.from_bytes(bs, "little")

        return NeonLogTxReturn(gas_used=gas_used, status=1, return_value=bytes())

    def _decode_neon_tx_ix(self, data_list: List[str]) -> Optional[NeonLogTxIx]:
        """Extracts gas_used of the """

        if len(data_list) != 1:
            self.error(f'Failed to decode neon tx cancel: should be 1 element in {data_list}')
            return None

        bs = base64.b64decode(data_list[0])
        gas_used = int.from_bytes(bs, "little")

        return NeonLogTxIx(gas_used=gas_used)

    def decode_neon_log(self, log_iter: Iterator[str]) -> NeonLogInfo:
        """Extracts Neon transaction result information"""

        sol_bpf_cycle_usage: Optional[SolLogBPFCycleUsage] = None
        sol_heap_usage: Optional[SolLogHeapUsage] = None
        neon_tx_sig: Optional[NeonLogTxSig] = None
        neon_tx_ix: Optional[NeonLogTxIx] = None
        neon_tx_return: Optional[NeonLogTxReturn] = None
        neon_tx_event_list: List[NeonLogTxEvent] = []

        for line in log_iter:
            if sol_bpf_cycle_usage is None:
                sol_bpf_cycle_usage = self._decode_bpf_cycle_usage(line)
                if sol_bpf_cycle_usage is not None:
                    continue
            elif sol_heap_usage is None:
                sol_heap_usage = self._decode_heap_usage(line)
                if sol_heap_usage is not None:
                    continue

            name, data_list = self._decode_mnemonic(line)
            if len(name) == 0:
                continue

            if name == 'HASH':
                if neon_tx_sig is None:
                    neon_tx_sig = self._decode_neon_tx_sig(data_list)
            elif name == 'RETURN':
                if neon_tx_return is None:
                    neon_tx_return = self._decode_neon_tx_return(data_list)
            elif name.startswith('LOG'):
                neon_tx_event = self._decode_neon_tx_event(data_list)
                if neon_tx_event is not None:
                    neon_tx_event_list.append(neon_tx_event)
            elif name == 'CL_TX_GAS':
                if neon_tx_return is None:
                    neon_tx_return = self._decode_neon_tx_cancel(data_list)
            elif name == 'IX_GAS':
                if neon_tx_ix is None:
                    neon_tx_ix = self._decode_neon_tx_ix(data_list)

        return NeonLogInfo(
            sol_bpf_cycle_usage=sol_bpf_cycle_usage,
            sol_heap_usage=sol_heap_usage,
            neon_tx_sig=neon_tx_sig,
            neon_tx_ix=neon_tx_ix,
            neon_tx_return=neon_tx_return,
            neon_tx_event_list=neon_tx_event_list
        )


def decode_log_list(log_list: Iterator[str]) -> NeonLogInfo:
    return _NeonLogDecoder().decode_neon_log(log_list)
