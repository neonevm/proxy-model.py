# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import logging
from abc import ABC, abstractmethod
from typing import List, Union, Optional

from .types import tcpConnectionTypes
from ...common.types import TcpOrTlsSocket
from ...common.constants import DEFAULT_BUFFER_SIZE, DEFAULT_MAX_SEND_SIZE


logger = logging.getLogger(__name__)


class TcpConnectionUninitializedException(Exception):
    pass


class TcpConnection(ABC):
    """TCP server/client connection abstraction.

    Main motivation of this class is to provide a buffer management
    when reading and writing into the socket.

    Implement the connection property abstract method to return
    a socket connection object.
    """

    def __init__(self, tag: int) -> None:
        self.tag: str = 'server' if tag == tcpConnectionTypes.SERVER else 'client'
        self.buffer: List[memoryview] = []
        self.closed: bool = False
        self._reusable: bool = False
        self._num_buffer = 0

    @property
    @abstractmethod
    def connection(self) -> TcpOrTlsSocket:
        """Must return the socket connection to use in this class."""
        raise TcpConnectionUninitializedException()     # pragma: no cover

    def send(self, data: Union[memoryview, bytes]) -> int:
        """Users must handle BrokenPipeError exceptions"""
        # logger.info(data.tobytes())
        return self.connection.send(data)

    def recv(
            self, buffer_size: int = DEFAULT_BUFFER_SIZE,
    ) -> Optional[memoryview]:
        """Users must handle socket.error exceptions"""
        data: bytes = self.connection.recv(buffer_size)
        if len(data) == 0:
            return None
        logger.debug(
            'received %d bytes from %s' %
            (len(data), self.tag),
        )
        # logger.info(data)
        return memoryview(data)

    def close(self) -> bool:
        if not self.closed:
            self.connection.close()
            self.closed = True
        return self.closed

    def has_buffer(self) -> bool:
        return self._num_buffer != 0

    def queue(self, mv: memoryview) -> None:
        self.buffer.append(mv)
        self._num_buffer += 1

    def flush(self, max_send_size: Optional[int] = None) -> int:
        """Users must handle BrokenPipeError exceptions"""
        if not self.has_buffer():
            return 0
        mv = self.buffer[0]
        # TODO: Assemble multiple packets if total
        # size remains below max send size.
        max_send_size = max_send_size or DEFAULT_MAX_SEND_SIZE
        sent: int = self.send(mv[:max_send_size])
        if sent == len(mv):
            self.buffer.pop(0)
            self._num_buffer -= 1
        else:
            self.buffer[0] = mv[sent:]
        del mv
        logger.debug('flushed %d bytes to %s' % (sent, self.tag))
        return sent

    def is_reusable(self) -> bool:
        return self._reusable

    def mark_inuse(self) -> None:
        self._reusable = False

    def reset(self) -> None:
        assert not self.closed
        self._reusable = True
        self.buffer = []
        self._num_buffer = 0
