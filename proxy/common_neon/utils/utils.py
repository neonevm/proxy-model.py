from __future__ import annotations
from typing import Dict, Any, List, Tuple
from enum import Enum

import json

from ..environment_data import LOG_FULL_OBJECT_INFO


class JsonBytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytearray):
            return obj.hex()
        if isinstance(obj, bytes):
            return obj.hex()
        return json.JSONEncoder.default(self, obj)


def str_fmt_object(obj: Any) -> str:
    type_name = 'Type'
    class_prefix = "<class '"

    def decode_value(value: Any) -> Tuple[bool, Any]:
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
                    has_item, item = decode_value(item)
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
        elif hasattr(value, '__dict__'):
            return True, lookup_dict(value.__dict__)
        elif isinstance(value, dict):
            return True, lookup_dict(value)
        elif hasattr(value, '__str__'):
            return True, str(value)
        else:
            return True, value
        return False, None

    def lookup_dict(d: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in d.items():
            has_value, value = decode_value(value)
            if not has_value:
                continue

            key = key.lstrip('_')
            result[key] = value
        return result

    name = f'{type(obj)}'
    name = name[name.rfind('.') + 1:-2]
    if name.startswith(class_prefix):
        name = name[len(class_prefix):]

    if hasattr(obj, '__dict__'):
        members = json.dumps(lookup_dict(obj.__dict__), skipkeys=True, sort_keys=True)
    elif isinstance(obj, dict):
        members = json.dumps(lookup_dict(obj), skipkeys=True, sort_keys=True)
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

