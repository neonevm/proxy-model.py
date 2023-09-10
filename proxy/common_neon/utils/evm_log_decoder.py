from __future__ import annotations

import base64
import enum
import logging
import re

from dataclasses import dataclass, asdict as dataclass_asdict
from typing import List, Iterator, Optional, Tuple, Dict, Any

from .utils import str_fmt_object, cached_method


LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class NeonLogTxReturn:
    gas_used: int
    status: int
    is_canceled: bool


@dataclass(frozen=True)
class NeonLogTxCancel:
    gas_used: int


@dataclass(frozen=True)
class NeonLogTxIx:
    gas_used: int
    total_gas_used: int


@dataclass(frozen=True)
class NeonLogTxEvent:
    class Type(enum.IntEnum):
        Log = 1

        EnterCall = 101
        EnterCallCode = 102
        EnterStaticCall = 103
        EnterDelegateCall = 104
        EnterCreate = 105
        EnterCreate2 = 106

        ExitStop = 201
        ExitReturn = 202
        ExitSelfDestruct = 203
        ExitRevert = 204

        Return = 300
        Cancel = 301

    event_type: Type
    is_hidden: bool

    address: bytes
    topic_list: List[bytes]
    data: bytes = b''

    sol_sig: str = ''
    idx: int = 0
    inner_idx: Optional[int] = None
    total_gas_used: int = 0
    is_reverted: bool = False
    event_level: int = 0
    event_order: int = 0

    @cached_method
    def __str__(self) -> str:
        return str_fmt_object(self)

    @staticmethod
    def from_dict(src: Dict[str, Any]) -> NeonLogTxEvent:
        src.update(dict(
            address=bytes.fromhex(src['address']),
            data=bytes.fromhex(src['data']),
            topic_list=[bytes.fromhex(t) for t in src['topic_list']]
        ))
        return NeonLogTxEvent(**src)

    def as_dict(self) -> Dict[str, Any]:
        res = dataclass_asdict(self)
        res.update(dict(
            address=self.address.hex(),
            data=self.data.hex(),
            topic_list=[t.hex() for t in self.topic_list]
        ))

        return res

    def is_exit_event_type(self) -> bool:
        return self.event_type in {
            NeonLogTxEvent.Type.ExitStop,
            NeonLogTxEvent.Type.ExitReturn,
            NeonLogTxEvent.Type.ExitSelfDestruct,
            NeonLogTxEvent.Type.ExitRevert
        }

    def is_start_event_type(self) -> bool:
        return self.event_type in {
            NeonLogTxEvent.Type.EnterCall,
            NeonLogTxEvent.Type.EnterCallCode,
            NeonLogTxEvent.Type.EnterStaticCall,
            NeonLogTxEvent.Type.EnterDelegateCall,
            NeonLogTxEvent.Type.EnterCreate,
            NeonLogTxEvent.Type.EnterCreate2
        }


@dataclass(frozen=True)
class NeonLogTxSig:
    neon_sig: bytes


@dataclass(frozen=True)
class NeonLogInfo:
    neon_tx_sig: Optional[NeonLogTxSig]
    neon_tx_ix: Optional[NeonLogTxIx]
    neon_tx_return: Optional[NeonLogTxReturn]
    neon_tx_event_list: List[NeonLogTxEvent]
    is_truncated: bool
    is_already_finalized: bool


class _NeonLogDecoder:
    _re_data = re.compile(r'^Program data: (.+)$')
    _log_truncated_msg = 'Log truncated'
    _is_already_finalized_msg = 'Program log: Storage Account is finalized'

    def _decode_mnemonic(self, line: str) -> Tuple[str, List[str]]:
        match = self._re_data.match(line)
        if match is None:
            return '', list()

        tail: str = match.group(1)
        data_list: List[str] = tail.split()
        if len(data_list) < 2:
            return '', list()

        mnemonic = base64.b64decode(data_list[0]).decode('utf-8')
        return mnemonic, data_list[1:]

    @staticmethod
    def _decode_neon_tx_return(neon_tx_ix: Optional[NeonLogTxIx], data_list: List[str]) -> Optional[NeonLogTxReturn]:
        """Unpacks base64-encoded return data"""
        if len(data_list) < 1:
            LOG.error(f'Failed to decode return data: less then 1 elements in {data_list}')
            return None

        bs = base64.b64decode(data_list[0])
        exit_status = int.from_bytes(bs, "little")
        exit_status = 0x1 if exit_status < 0xd0 else 0x0

        if neon_tx_ix is None:
            LOG.error(f'Failed to get total gas for RETURN')
            return None
        else:
            gas_used = neon_tx_ix.total_gas_used

        return NeonLogTxReturn(gas_used=gas_used, status=exit_status, is_canceled=False)

    @staticmethod
    def _decode_neon_tx_enter(data_list: List[str]) -> Optional[NeonLogTxEvent]:
        """
        Unpacks base64-encoded event data:
        ENTER CALL <20 bytes contract address>
        ENTER CALLCODE <20 bytes contract address>
        ENTER STATICCALL <20 bytes contract address>
        ENTER DELEGATECALL <20 bytes contract address>
        ENTER CREATE <20 bytes contract address>
        ENTER CREATE2 <20 bytes contract address>
        """
        if len(data_list) != 2:
            LOG.error(f'Failed to decode ENTER event, it does not contain 2 elements: {len(data_list)}, {data_list}')
            return None

        type_name = base64.b64decode(data_list[0]).decode('utf-8')
        if type_name == 'CALL':
            event_type = NeonLogTxEvent.Type.EnterCall
        elif type_name == 'CALLCODE':
            event_type = NeonLogTxEvent.Type.EnterCallCode
        elif type_name == 'STATICCALL':
            event_type = NeonLogTxEvent.Type.EnterStaticCall
        elif type_name == 'DELEGATECALL':
            event_type = NeonLogTxEvent.Type.EnterDelegateCall
        elif type_name == 'CREATE':
            event_type = NeonLogTxEvent.Type.EnterCreate
        elif type_name == 'CREATE2':
            event_type = NeonLogTxEvent.Type.EnterCreate2
        else:
            LOG.error(f'Failed to decode enter event, wrong type: {type_name}')
            return None

        address = base64.b64decode(data_list[1])
        if len(address) != 20:
            LOG.error(f'Failed to decode enter event, address has wrong length: {address}')
            return None

        return NeonLogTxEvent(event_type=event_type, is_hidden=True, address=address, topic_list=list())

    @staticmethod
    def _decode_neon_tx_exit(data_list: List[str]) -> Optional[NeonLogTxEvent]:
        """
        Unpacks base64-encoded event data:
        EXIT STOP
        EXIT RETURN
        EXIT SELFDESTRUCT
        EXIT REVERT data
        """
        if len(data_list) < 1:
            LOG.error(f'Failed to decode EXIT event, it contains less that 1 element: {len(data_list)}, {data_list}')
            return None

        type_name = base64.b64decode(data_list[0]).decode('utf-8')

        if type_name == 'STOP':
            event_type = NeonLogTxEvent.Type.ExitStop
        elif type_name == 'RETURN':
            event_type = NeonLogTxEvent.Type.ExitReturn
        elif type_name == 'SELFDESTRUCT':
            event_type = NeonLogTxEvent.Type.ExitSelfDestruct
        elif type_name == 'REVERT':
            event_type = NeonLogTxEvent.Type.ExitRevert
        else:
            LOG.error(f'Failed to decode exit event, wrong type: {type_name}')
            return None

        data = b''
        if len(data_list) > 1:
            data = base64.b64decode(data_list[1])

        return NeonLogTxEvent(event_type=event_type, is_hidden=True, address=b'', data=data, topic_list=list())

    @staticmethod
    def _decode_neon_tx_event(log_num: int, data_list: List[str]) -> Optional[NeonLogTxEvent]:
        """
        Unpacks base64-encoded event data:
        LOG0 address [0] data
        LOG1 address [1] topic1 data
        LOG2 address [2] topic1 topic2 data
        LOG3 address [3] topic1 topic2 topic3 data
        LOG4 address [4] topic1 topic2 topic3 topic4 data
        """

        if len(data_list) < 3:
            LOG.error(f'Failed to decode events data: less 3 elements in {data_list}')
            return None

        if (log_num > 4) or (log_num < 0):
            LOG.error(f'Failed to decode events data: count of topics = {log_num}')
            return None

        bs = base64.b64decode(data_list[1])
        topic_cnt = int.from_bytes(bs, 'little')
        if topic_cnt != log_num:
            LOG.error(f'Failed to decode events data: log_num ({log_num}) != topic_cnt({topic_cnt})')
            return None

        address = base64.b64decode(data_list[0])
        topic_list = [base64.b64decode(data_list[2 + i]) for i in range(topic_cnt)]

        data_index = 2 + topic_cnt
        data = base64.b64decode(data_list[data_index]) if data_index < len(data_list) else b''

        event_type = NeonLogTxEvent.Type.Log

        return NeonLogTxEvent(event_type=event_type, is_hidden=False, address=address, topic_list=topic_list, data=data)

    @staticmethod
    def _decode_neon_tx_sig(data_list: List[str]) -> Optional[NeonLogTxSig]:
        """Extracts Neon transaction hash"""
        if len(data_list) != 1:
            LOG.error(f'Failed to decode neon tx hash: should be 1 element in {data_list}')
            return None

        tx_sig = base64.b64decode(data_list[0])
        if len(tx_sig) != 32:
            LOG.error(f'Failed to decode neon tx hash: wrong hash length in {data_list}')
            return None

        return NeonLogTxSig(neon_sig=tx_sig)

    @staticmethod
    def _decode_neon_tx_gas(data_list: List[str]) -> Optional[NeonLogTxIx]:
        """
        GAS <32 bytes le iteration gas> <32 bytes le total gas>
        """
        if len(data_list) != 2:
            LOG.error(f'Failed to decode neon ix gas : should be 1 element in {data_list}')
            return None

        bs = base64.b64decode(data_list[0])
        gas_used = int.from_bytes(bs, "little")

        bs = base64.b64decode(data_list[1])
        total_gas_used = int.from_bytes(bs, "little")

        return NeonLogTxIx(gas_used=gas_used, total_gas_used=total_gas_used)

    def decode_neon_log(self, log_iter: Iterator[str]) -> NeonLogInfo:
        """Extracts Neon transaction result information"""

        neon_tx_sig: Optional[NeonLogTxSig] = None
        neon_tx_ix: Optional[NeonLogTxIx] = None
        neon_tx_return: Optional[NeonLogTxReturn] = None
        neon_tx_event_list: List[NeonLogTxEvent] = list()
        is_truncated = False
        is_already_finalized = False

        for line in log_iter:
            if line == self._log_truncated_msg:
                is_truncated = True
                continue
            elif line == self._is_already_finalized_msg:
                is_already_finalized = True
                continue

            name, data_list = self._decode_mnemonic(line)
            if len(name) == 0:
                continue

            if name == 'HASH':
                if neon_tx_sig is None:
                    neon_tx_sig = self._decode_neon_tx_sig(data_list)
                else:
                    LOG.warning('HASH is already exist!')
            elif name == 'RETURN':
                if neon_tx_return is None:
                    neon_tx_return = self._decode_neon_tx_return(neon_tx_ix, data_list)
                else:
                    LOG.warning('RETURN is already exist!')
            elif name.startswith('LOG'):
                neon_tx_event = self._decode_neon_tx_event(int(name[3:]), data_list)
                if neon_tx_event is not None:
                    neon_tx_event_list.append(neon_tx_event)
            elif name == 'ENTER':
                neon_tx_event = self._decode_neon_tx_enter(data_list)
                if neon_tx_event is not None:
                    neon_tx_event_list.append(neon_tx_event)
            elif name == 'EXIT':
                neon_tx_event = self._decode_neon_tx_exit(data_list)
                if neon_tx_event is not None:
                    neon_tx_event_list.append(neon_tx_event)
            elif name == 'GAS':
                if neon_tx_ix is None:
                    neon_tx_ix = self._decode_neon_tx_gas(data_list)
                else:
                    LOG.warning('GAS is already exist!')

        return NeonLogInfo(
            neon_tx_sig=neon_tx_sig,
            neon_tx_ix=neon_tx_ix,
            neon_tx_return=neon_tx_return,
            neon_tx_event_list=neon_tx_event_list,
            is_truncated=is_truncated,
            is_already_finalized=is_already_finalized
        )


def decode_log_list(log_list: Iterator[str]) -> NeonLogInfo:
    return _NeonLogDecoder().decode_neon_log(log_list)
