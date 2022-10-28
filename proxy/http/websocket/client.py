# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import base64
import socket
import secrets
import selectors
from typing import Callable, Optional

from .frame import WebsocketFrame
from ..parser import HttpParser, httpParserTypes
from ...common.types import TcpOrTlsSocket
from ...common.utils import (
    text_, new_socket_connection, build_websocket_handshake_request,
)
from ...core.connection import TcpConnection, tcpConnectionTypes
from ...common.constants import (
    DEFAULT_BUFFER_SIZE, DEFAULT_SELECTOR_SELECT_TIMEOUT,
)


class WebsocketClient(TcpConnection):
    """Websocket client connection.

    TODO: Make me compatible with the work framework."""

    def __init__(
        self,
        hostname: bytes,
        port: int,
        path: bytes = b'/',
        on_message: Optional[Callable[[WebsocketFrame], None]] = None,
    ) -> None:
        super().__init__(tcpConnectionTypes.CLIENT)
        self.hostname: bytes = hostname
        self.port: int = port
        self.path: bytes = path
        self.sock: socket.socket = new_socket_connection(
            (socket.gethostbyname(text_(self.hostname)), self.port),
        )
        self.on_message: Optional[
            Callable[
                [
                    WebsocketFrame,
                ],
                None,
            ]
        ] = on_message
        self.selector: selectors.DefaultSelector = selectors.DefaultSelector()

    @property
    def connection(self) -> TcpOrTlsSocket:
        return self.sock

    def handshake(self) -> None:
        """Start websocket upgrade & handshake protocol"""
        self.upgrade()
        self.sock.setblocking(False)

    def upgrade(self) -> None:
        """Creates a key and sends websocket handshake packet to upstream.
        Receives response from the server and asserts that websocket
        accept header is valid in the response."""
        key = base64.b64encode(secrets.token_bytes(16))
        self.sock.send(
            build_websocket_handshake_request(
                key,
                url=self.path,
                host=self.hostname,
            ),
        )
        response = HttpParser(httpParserTypes.RESPONSE_PARSER)
        response.parse(memoryview(self.sock.recv(DEFAULT_BUFFER_SIZE)))
        accept = response.header(b'Sec-Websocket-Accept')
        assert WebsocketFrame.key_to_accept(key) == accept

    def shutdown(self, _data: Optional[bytes] = None) -> None:
        """Closes connection with the server."""
        super().close()

    def run_once(self) -> bool:
        ev = selectors.EVENT_READ
        if self.has_buffer():
            ev |= selectors.EVENT_WRITE
        self.selector.register(self.sock.fileno(), ev)
        events = self.selector.select(timeout=DEFAULT_SELECTOR_SELECT_TIMEOUT)
        self.selector.unregister(self.sock)
        for _, mask in events:
            if mask & selectors.EVENT_READ and self.on_message:
                # TODO: client recvbuf size flag currently not used here
                raw = self.recv()
                if raw is None or raw == b'':
                    self.closed = True
                    return True
                frame = WebsocketFrame()
                frame.parse(raw.tobytes())
                self.on_message(frame)
            elif mask & selectors.EVENT_WRITE:
                # TODO: max sendbuf size flag currently not used here
                self.flush()
        return False

    def run(self) -> None:
        try:
            while not self.closed:
                if self.run_once():
                    break
        except KeyboardInterrupt:
            pass
        finally:
            if not self.closed:
                self.selector.unregister(self.sock)
                try:
                    self.sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            self.sock.close()
            self.selector.close()
