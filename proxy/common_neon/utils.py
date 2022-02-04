from typing import Dict, Optional, Any
import json


class SolanaBlockInfo:
    def __init__(self, slot=None, finalized=False, height=None, hash=None, parent_hash=None, time=None, signs=None):
        self.slot = slot
        self.finalized = finalized
        self.height = height
        self.hash = hash
        self.parent_hash = parent_hash
        self.time = time
        self.signs = signs

    def __str__(self):
        return str_fmt_object(self)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, src):
        self.__dict__ = src


def str_fmt_object(obj):
    name = f'{type(obj)}'
    name = name[name.rfind('.') + 1:-2]
    lookup = lambda o: o.__dict__ if hasattr(o, '__dict__') else None
    members = {json.dumps(obj, skipkeys=True, default=lookup, sort_keys=True)}
    return f'{name}: {members}'


def get_from_dict(src: Dict, *path) -> Optional[Any]:
    """Provides smart getting values from python dictionary"""
    val = src
    for key in path:
        if not isinstance(val, dict):
            return None
        val = val.get(key)
        if val is None:
            return None
    return val
