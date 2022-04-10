import abc
import multiprocessing as mp
import os
import signal

from multiprocessing.managers import BaseManager
from dataclasses import dataclass, astuple, field
from typing import Tuple, Dict, Any

from logged_groups import logged_group


@dataclass
class ServiceInvocation:
    method_name: str = None
    args: Tuple[Any] = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)


class QueueBasedServiceClient:

    def __init__(self, host: str, port: int):
        class MemPoolQueueManager(BaseManager):
            pass

        MemPoolQueueManager.register('get_queue')
        queue_manager = MemPoolQueueManager(address=(host, port), authkey=b'abracadabra')
        queue_manager.connect()
        self._queue = queue_manager.get_queue()

    def invoke(self, method_name, *args, **kwargs):
        invocation = ServiceInvocation(method_name=method_name, args=args, kwargs=kwargs)

        self._queue.put(invocation)


@logged_group("neon")
class QueueBasedService(abc.ABC):

    QUEUE_TIMEOUT_SEC = 0.4
    BREAK_PROC_INVOCATION = 0
    JOIN_PROC_TIMEOUT_SEC = 5

    def __init__(self, *, port: int, is_background: bool):
        self._queue = mp.Queue()
        self._port = port
        self._is_back_ground = is_background

        class MemPoolQueueManager(BaseManager):
            pass

        MemPoolQueueManager.register("get_queue", callable=lambda: self._queue)
        self._queue_manager = MemPoolQueueManager(address=('', port), authkey=b'abracadabra')
        self._mempool_server = self._queue_manager.get_server()
        self._mempool_server_process = mp.Process(target=self._mempool_server.serve_forever, name="mempool_service")
        self._queue_process = mp.Process(target=self.run, name="mempool_queue_proc")
        self._timeout = self.QUEUE_TIMEOUT_SEC

        pid = os.getpid()
        signal.signal(signal.SIGINT, lambda sif, frame: self.finish() if os.getpid() == pid else 0)

    def start(self):
        self.info(f"Starting queue server: {self._port}")
        self._mempool_server_process.start()
        self._queue_process.start()
        if not self._is_back_ground:
            self._queue_process.join()

    def run(self):
        self.service_process_init()
        while True:
            try:
                if not self._run_impl():
                    break
            except BaseException as e:
                self.do_extras()

    def _run_impl(self) -> bool:

        invocation = self._queue.get(block=True, timeout=self._timeout)
        if invocation == self.BREAK_PROC_INVOCATION:
            return False
        self.dispatch(invocation)
        return True

    def dispatch(self, invocation: ServiceInvocation):
        method_name, args, kwargs = astuple(invocation)
        handler = getattr(self, method_name, None)
        if handler is None:
            raise NotImplementedError(f"Process has no handler for {handler}")
        handler(*args, **kwargs)

    def finish(self):
        self.info("Finishing the queue and listening processes")
        self._mempool_server_process.terminate()
        if not self._queue_process.is_alive():
            return
        self._queue.put_nowait(self.BREAK_PROC_INVOCATION)
        self._queue_process.join(timeout=self.JOIN_PROC_TIMEOUT_SEC)

    @abc.abstractmethod
    def do_extras(self):
        assert "To be implemented in derived class"

    @abc.abstractmethod
    def service_process_init(self):
        assert "To be implemented in derived class"
