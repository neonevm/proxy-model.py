# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       pre
"""
import socket
import logging
import argparse
import selectors
import threading
import multiprocessing
import multiprocessing.synchronize
from typing import Dict, List, Tuple, Optional
from multiprocessing import connection
from multiprocessing.reduction import recv_handle

from ..work import start_threaded_work, delegate_work_to_pool
from ..event import EventQueue
from ..work.fd import LocalFdExecutor
from ...common.flag import flags
from ...common.types import HostPort
from ...common.logger import Logger
from ...common.backports import NonBlockingQueue
from ...common.constants import DEFAULT_LOCAL_EXECUTOR


logger = logging.getLogger(__name__)


flags.add_argument(
    '--local-executor',
    type=int,
    default=int(DEFAULT_LOCAL_EXECUTOR),
    help='Default: ' + ('1' if DEFAULT_LOCAL_EXECUTOR else '0') + '.  ' +
    'Enabled by default.  Use 0 to disable.  When enabled acceptors ' +
    'will make use of local (same process) executor instead of distributing load across ' +
    'remote (other process) executors.  Enable this option to achieve CPU affinity between ' +
    'acceptors and executors, instead of using underlying OS kernel scheduling algorithm.',
)


class Acceptor(multiprocessing.Process):
    """Work acceptor process.

    On start-up, `Acceptor` accepts a file descriptor which will be used to
    accept new work.  File descriptor is accepted over a `fd_queue`.

    `Acceptor` goes on to listen for new work over the received server socket.
    By default, `Acceptor` will spawn a new thread to handle each work.

    However, when ``--threadless`` option is enabled without ``--local-executor``,
    `Acceptor` process will also pre-spawns a
    :class:`~proxy.core.acceptor.threadless.Threadless` process during start-up.
    Accepted work is delegated to these :class:`~proxy.core.acceptor.threadless.Threadless`
    processes. `Acceptor` process shares accepted work with a
    :class:`~proxy.core.acceptor.threadless.Threadless` process over it's dedicated pipe.
    """

    def __init__(
            self,
            idd: int,
            fd_queue: connection.Connection,
            flags: argparse.Namespace,
            lock: 'multiprocessing.synchronize.Lock',
            # semaphore: multiprocessing.synchronize.Semaphore,
            executor_queues: List[connection.Connection],
            executor_pids: List[int],
            executor_locks: List['multiprocessing.synchronize.Lock'],
            event_queue: Optional[EventQueue] = None,
    ) -> None:
        super().__init__()
        self.flags = flags
        # Eventing core queue
        self.event_queue = event_queue
        # Index assigned by `AcceptorPool`
        self.idd = idd
        # Mutex used for synchronization with acceptors
        self.lock = lock
        # self.semaphore = semaphore
        # Queue over which server socket fd is received on start-up
        self.fd_queue: connection.Connection = fd_queue
        # Available executors
        self.executor_queues = executor_queues
        self.executor_pids = executor_pids
        self.executor_locks = executor_locks
        # Selector
        self.running = multiprocessing.Event()
        self.selector: Optional[selectors.DefaultSelector] = None
        # File descriptors used to accept new work
        self.socks: Dict[int, socket.socket] = {}
        # Internals
        self._total: Optional[int] = None
        self._local_work_queue: Optional['NonBlockingQueue'] = None
        self._local: Optional[LocalFdExecutor] = None
        self._lthread: Optional[threading.Thread] = None

    def accept(
            self,
            events: List[Tuple[selectors.SelectorKey, int]],
    ) -> List[Tuple[socket.socket, Optional[HostPort]]]:
        works = []
        for key, mask in events:
            if mask & selectors.EVENT_READ:
                try:
                    conn, addr = self.socks[key.data].accept()
                    logging.debug(
                        'Accepting new work#{0}'.format(conn.fileno()),
                    )
                    works.append((conn, addr or None))
                except BlockingIOError:
                    # logger.info('blocking io error')
                    pass
        return works

    def run_once(self) -> None:
        if self.selector is not None:
            events = self.selector.select(timeout=1)
            if len(events) == 0:
                return
            # locked = False
            # try:
            #     if self.lock.acquire(block=False):
            #         locked = True
            #         self.semaphore.release()
            # finally:
            #     if locked:
            #         self.lock.release()
            locked, works = False, []
            try:
                # if not self.semaphore.acquire(False, None):
                #     return
                if self.lock.acquire(block=False):
                    locked = True
                    works = self.accept(events)
            finally:
                if locked:
                    self.lock.release()
            for work in works:
                if self.flags.threadless and \
                        self.flags.local_executor:
                    assert self._local_work_queue
                    self._local_work_queue.put(work)
                else:
                    self._work(*work)

    def run(self) -> None:
        Logger.setup(
            self.flags.log_file, self.flags.log_level,
            self.flags.log_format,
        )
        self.selector = selectors.DefaultSelector()
        try:
            self._recv_and_setup_socks()
            if self.flags.threadless and self.flags.local_executor:
                self._start_local()
            for fileno in self.socks:
                self.selector.register(
                    fileno, selectors.EVENT_READ, fileno,
                )
            while not self.running.is_set():
                self.run_once()
        except KeyboardInterrupt:
            pass
        finally:
            for fileno in self.socks:
                self.selector.unregister(fileno)
            if self.flags.threadless and self.flags.local_executor:
                self._stop_local()
            for fileno in self.socks:
                self.socks[fileno].close()
            self.socks.clear()
            self.selector.close()
            logger.debug('Acceptor#%d shutdown', self.idd)

    def _recv_and_setup_socks(self) -> None:
        # TODO: Use selector on fd_queue so that we can
        # dynamically accept from new fds.
        for _ in range(self.fd_queue.recv()):
            fileno = recv_handle(self.fd_queue)
            # TODO: Convert to socks i.e. list of fds
            self.socks[fileno] = socket.fromfd(
                fileno,
                family=self.flags.family,
                type=socket.SOCK_STREAM,
            )
        self.fd_queue.close()

    def _start_local(self) -> None:
        assert self.socks
        self._local_work_queue = NonBlockingQueue()
        self._local = LocalFdExecutor(
            iid=self.idd,
            work_queue=self._local_work_queue,
            flags=self.flags,
            event_queue=self.event_queue,
        )
        self._lthread = threading.Thread(target=self._local.run)
        self._lthread.daemon = True
        self._lthread.start()

    def _stop_local(self) -> None:
        if self._lthread is not None and \
                self._local_work_queue is not None:
            self._local_work_queue.put(False)
            self._lthread.join()

    def _work(self, conn: socket.socket, addr: Optional[HostPort]) -> None:
        self._total = self._total or 0
        if self.flags.threadless:
            # Index of worker to which this work should be dispatched
            # Use round-robin strategy by default.
            #
            # By default all acceptors will start sending work to
            # 1st workers.  To randomize, we offset index by idd.
            index = (self._total + self.idd) % self.flags.num_workers
            thread = threading.Thread(
                target=delegate_work_to_pool,
                args=(
                    self.executor_pids[index],
                    self.executor_queues[index],
                    self.executor_locks[index],
                    conn,
                    addr,
                    self.flags.unix_socket_path,
                ),
            )
            thread.start()
            # TODO: Move me into target method
            logger.debug(   # pragma: no cover
                'Dispatched work#{0}.{1}.{2} to worker#{3}'.format(
                    conn.fileno(), self.idd, self._total, index,
                ),
            )
        else:
            _, thread = start_threaded_work(
                self.flags,
                conn,
                addr,
                event_queue=self.event_queue,
                publisher_id=self.__class__.__name__,
            )
            # TODO: Move me into target method
            logger.debug(   # pragma: no cover
                'Started work#{0}.{1}.{2} in thread#{3}'.format(
                    conn.fileno(), self.idd, self._total, thread.ident,
                ),
            )
        self._total += 1
