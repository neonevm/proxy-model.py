import multiprocessing as mp
import queue
from dataclasses import dataclass, astuple
from typing import Tuple, Dict, Any
from abc import ABC, abstractmethod


@dataclass
class Invocation:
    handler: str
    args: Tuple[Any]
    kvargs: Dict[str, Any]


class BaseProcess(mp.Process):
    """A process backed by an internal queue for simple one-way message passing"""

    QUEUE_TIMEOUT_SEC = 1
    BREAK_PROC_INVOCATION = 0

    def __init__(self, *args, **kwargs):
        self.__queue = mp.Queue
        super().__init__(*args, **kwargs)
        self._queue = mp.Queue()
        self._timeout = BaseProcess.QUEUE_TIMEOUT_SEC

    def send(self, handler, *args, **kvargs):
        """Puts the event and args as a `Msg` on the queue"""
        invocation = Invocation(handler=handler, args=args, kvargs=kvargs)
        self._queue.put(invocation)

    def finish(self):
        self._queue.put(BaseProcess.BREAK_PROC_INVOCATION)

    def dispatch(self, invocation: Invocation):
        handler, args, kvargs = astuple(invocation)

        handler = getattr(self, handler, None)
        if handler is None:
            raise NotImplementedError(f"Process has no handler for {handler}")

        handler(*args, **kvargs)

    def run(self):
        while True:
            try:
                if not self._run_impl():
                    break
            except queue.Empty:
                self.do_extras()

    def _run_impl(self) -> bool:
        invocation = self._queue.get(block=True, timeout=self._timeout)
        if invocation == BaseProcess.BREAK_PROC_INVOCATION:
            return False
        self.dispatch(invocation)
        return True

    @abstractmethod
    def do_extras(self):
        assert "Should be implemented"
