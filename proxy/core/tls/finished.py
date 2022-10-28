# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Tuple, Optional


class TlsFinished:
    """TLS Finished"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        return False, raw

    def build(self) -> bytes:
        assert self.data
        return self.data
