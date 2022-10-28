# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import socket
import logging
from typing import Any, TypeVar, Optional

from ...event import eventNames
from ..threadless import Threadless
from ....common.types import HostPort, TcpOrTlsSocket


T = TypeVar('T')

logger = logging.getLogger(__name__)


class ThreadlessFdExecutor(Threadless[T]):
    """A threadless executor which handles file descriptors
    and works with read/write events over a socket."""

    def work(self, *args: Any) -> None:
        fileno: int = args[0]
        addr: Optional[HostPort] = args[1]
        conn: Optional[TcpOrTlsSocket] = args[2]
        conn = conn or socket.fromfd(
            fileno, family=socket.AF_INET if self.flags.hostname.version == 4 else socket.AF_INET6,
            type=socket.SOCK_STREAM,
        )
        uid = '%s-%s-%s' % (self.iid, self._total, fileno)
        self.works[fileno] = self.create(uid, conn, addr)
        self.works[fileno].publish_event(
            event_name=eventNames.WORK_STARTED,
            event_payload={'fileno': fileno, 'addr': addr},
            publisher_id=self.__class__.__name__,
        )
        try:
            self.works[fileno].initialize()
            self._total += 1
        except Exception as e:
            logger.exception(   # pragma: no cover
                'Exception occurred during initialization',
                exc_info=e,
            )
            self._cleanup(fileno)
