from __future__ import annotations

import hashlib
import time
from enum import Enum
from typing import Dict, Any, List, Tuple

from ..environment_data import LOG_FULL_OBJECT_INFO


def str_fmt_object(obj: Any, skip_prefix=True) -> str:
    type_name = 'Type'
    class_prefix = "<class '"

    def _has_precalculated_str(value: Any) -> bool:
        value = getattr(value, '_str', None)
        return isinstance(value, str) and (len(value) > 0)

    def _decode_value(value: Any) -> Tuple[bool, Any]:
        if callable(value):
            if LOG_FULL_OBJECT_INFO:
                return True, 'callable...'
        elif value is None:
            if LOG_FULL_OBJECT_INFO:
                return True, value
        elif isinstance(value, bool):
            if value or LOG_FULL_OBJECT_INFO:
                return True, value
        elif isinstance(value, Enum):
            value = str(value)
            idx = value.find('.')
            if idx != -1:
                value = value[idx + 1:]
            return True, value
        elif isinstance(value, list) or isinstance(value, set):
            if LOG_FULL_OBJECT_INFO:
                result_list: List[Any] = []
                for item in value:
                    has_item, item = _decode_value(item)
                    result_list.append(item if has_item else '?...')
                return True, result_list
            elif len(value) > 0:
                return True, f'len={len(value)}'
        elif isinstance(value, str) or isinstance(value, bytes) or isinstance(value, bytearray):
            if (not LOG_FULL_OBJECT_INFO) and (len(value) == 0):
                return False, None
            if isinstance(value, bytes) or isinstance(value, bytearray):
                value = value.hex()
            if (not LOG_FULL_OBJECT_INFO) and (value[:2] in {'0x', '0X'}):
                value = value[2:]
            if (not LOG_FULL_OBJECT_INFO) and (len(value) > 20):
                value = value[:20] + '...'
            return True, value
        elif _has_precalculated_str(value):
            return True, getattr(value, '_str')
        elif hasattr(value, '__dict__'):
            return True, _lookup_dict(value.__dict__)
        elif isinstance(value, dict):
            return True, _lookup_dict(value)
        elif hasattr(value, '__str__'):
            return True, str(value)
        else:
            return True, value
        return False, None

    def _lookup_dict(d: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in d.items():
            if not isinstance(key, str):
                key = str(key)
            if skip_prefix and key.startswith('_'):
                continue
            if key == '_str':
                continue

            has_value, value = _decode_value(value)
            if not has_value:
                continue

            result[key.strip('_')] = value
        return result

    name = f'{type(obj)}'
    name = name[name.rfind('.') + 1:-2]
    if name.startswith(class_prefix):
        name = name[len(class_prefix):]

    if hasattr(obj, '__dict__'):
        members = _lookup_dict(obj.__dict__)
    elif isinstance(obj, dict):
        members = _lookup_dict(obj)
    else:
        members = None

    return f'<{type_name} {name}>: {members}'


def get_from_dict(src: Dict, *path) -> Any:
    """Provides smart getting values from python dictionary"""
    val = src
    for key in path:
        if not isinstance(val, dict):
            return None
        val = val.get(key)
        if val is None:
            return None
    return val


def gen_unique_id():
    return hashlib.md5((time.time_ns()).to_bytes(16, 'big')).hexdigest()[:7]
