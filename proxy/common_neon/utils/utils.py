from __future__ import annotations

import functools
import hashlib
import time
import os

from enum import Enum
from typing import Dict, Any, Tuple, List, Set, Union


LOG_FULL_OBJECT_INFO = os.environ.get('LOG_FULL_OBJECT_INFO', 'NO').upper() in ('YES', 'ON', 'TRUE')
try:
    LOG_OBJECT_INFO_LIMIT = int(os.environ.get('LOG_OBJECT_INFO_LIMIT', None))
except (BaseException,):
    LOG_OBJECT_INFO_LIMIT = 2 ** 64


def cached_method(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # validate:
        # class A:
        #    def func(self):
        #       ....
        #
        # assert len(args) == 1
        # assert isinstance(args[0], object)

        self = args[0]
        try:
            return getattr(self, wrapper._cached_value_name)
        except AttributeError:
            pass

        value = func(*args, **kwargs)
        object.__setattr__(self, wrapper._cached_value_name, value)
        return value

    def reset_cache(self):
        if hasattr(self, wrapper._cached_value_name):
            object.__delattr__(self, wrapper._cached_value_name)

    wrapper._cached_value_name = '_cached_' + wrapper.__name__
    wrapper.reset_cache = reset_cache
    return wrapper


cached_property = functools.cached_property


@functools.lru_cache(maxsize=None)
def str_enum(value: Enum) -> str:
    value = str(value)
    idx = value.find('.')
    if idx != -1:
        value = value[idx + 1:]
    return value


def str_fmt_object(obj: Any, skip_underling=True, name='') -> str:
    def _decode_name(value: Any) -> str:
        result = f'{type(value)}'
        result = result[result.rfind('.') + 1:-2]
        class_prefix = '<class '
        if result.startswith(class_prefix):
            result = result[len(class_prefix) + 1:]
        return result

    def _lookup_dict_as_value(value_type: str, value: Dict[str, Any]) -> Tuple[bool, str]:
        result = _lookup_dict(value)
        if (not LOG_FULL_OBJECT_INFO) and (len(result) == 0):
            return False, '?'

        return True, value_type + '({' + result + '})'

    def _lookup_str_as_value(value: Union[str, bytes, bytearray]) -> Tuple[bool, str]:
        if (not LOG_FULL_OBJECT_INFO) and (len(value) == 0):
            return False, '?'

        if isinstance(value, bytes) or isinstance(value, bytearray):
            value = value.hex()
        if (not LOG_FULL_OBJECT_INFO) and (value[:2] in {'0x', '0X'}):
            value = value[2:]
        if (not LOG_FULL_OBJECT_INFO) and (len(value) > 20):
            value = value[:20] + '...'
        return True, "'" + value + "'"

    def _lookup_list_as_value(value_list: Union[Set[Any], List[Any]]) -> Tuple[bool, str]:
        value_list_type = 'list' if isinstance(value_list, list) else 'set'

        if LOG_FULL_OBJECT_INFO:
            idx = 0
            result = ''
            for item in value_list:
                has_item, item = _decode_value(item)
                idx += 1
                if idx > 1:
                    result += ', '
                result += (item if has_item else '?...')
            return True, value_list_type + '([' + result + '])'

        elif len(value_list) == 0:
            return False, '?'

        return True, value_list_type + '(len=' + str(len(value_list)) + ', [...])'

    def _decode_value(value: Any) -> Tuple[bool, str]:
        if callable(value):
            if LOG_FULL_OBJECT_INFO:
                return True, 'callable(...)'
        elif value is None:
            if LOG_FULL_OBJECT_INFO:
                return True, 'None'
        elif isinstance(value, bool):
            if value or LOG_FULL_OBJECT_INFO:
                return True, str(value)
        elif isinstance(value, Enum):
            return True, str_enum(value)
        elif isinstance(value, list) or isinstance(value, set):
            return _lookup_list_as_value(value)
        elif isinstance(value, str) or isinstance(value, bytes) or isinstance(value, bytearray):
            return _lookup_str_as_value(value)
        elif isinstance(value, dict):
            return _lookup_dict_as_value('dict', value)
        elif hasattr(value, '__str__'):
            value = str(value)
            if LOG_FULL_OBJECT_INFO or (len(value) > 0):
                return True, value
        elif hasattr(value, '__dict__'):
            return _lookup_dict_as_value(_decode_name(value), value.__dict__)
        return False, '?'

    def _lookup_dict(d: Dict[str, Any]) -> str:
        idx = 0
        result = ''
        for key, value in d.items():
            if not isinstance(key, str):
                key = str(key)
            if skip_underling and key.startswith('_'):
                continue

            has_value, value = _decode_value(value)
            if not has_value:
                continue

            if idx > 0:
                result += ', '
            result += key.strip('_') + '=' + value
            idx += 1
            if (not LOG_FULL_OBJECT_INFO) and (idx >= LOG_OBJECT_INFO_LIMIT):
                break
        return result

    if len(name) == 0:
        name = _decode_name(obj)

    if hasattr(obj, '__dict__'):
        content = _lookup_dict(obj.__dict__)
    elif isinstance(obj, dict):
        content = _lookup_dict(obj)
    else:
        content = None

    return name + '(' + content + ')'


def get_from_dict(src: Dict, path: Tuple[Any, ...], default_value: Any) -> Any:
    """Provides smart getting values from python dictionary"""
    value = src
    for key in path:
        if not isinstance(value, dict):
            return default_value

        value = value.get(key, None)
        if value is None:
            return default_value
    return value


def gen_unique_id():
    return hashlib.md5((time.time_ns()).to_bytes(16, 'big')).hexdigest()[:7]
