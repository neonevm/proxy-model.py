import json
import logging
import threading
import contextlib
from logging import LogRecord, Filter
from datetime import datetime


class JSONFormatter(logging.Formatter):
    def format(self, record: LogRecord) -> str:
        message_dict = {
            "level": record.levelname,
            "date": datetime.fromtimestamp(record.created).isoformat(),
            "module": f"{record.filename}:{record.lineno}",
            "process": record.process
        }
        if isinstance(record.msg, dict):
            message_dict.update(record.msg)
        else:
            message_dict["message"] = record.getMessage()
        if hasattr(record, "context"):
            context = {}
            if isinstance(record.context, str):
                try:
                    context = json.loads(record.context)
                except json.JSONDecodeError:
                    context = {"context": record.context}
            elif isinstance(record.context, dict):
                context = record.context
            message_dict.update(context)

        if record.exc_info:
            message_dict["exc_info"] = record.exc_info
            message_dict["exc_text"] = record.exc_text

        return json.dumps(message_dict)


class ContextFilter(Filter):
    def filter(self, record: LogRecord) -> bool:
        thread = threading.current_thread()
        log_context = {}
        if hasattr(thread, "log_context"):
            log_context = thread.log_context
        record.context = log_context
        return True


@contextlib.contextmanager
def logging_context(**kwargs):
    thread = threading.current_thread()
    if not hasattr(thread, "log_context"):
        thread.log_context = {}
    thread.log_context.update(kwargs)
    yield
    thread.log_context = {}
