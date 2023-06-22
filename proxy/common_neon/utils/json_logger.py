import json
import logging
import threading
import contextlib
import traceback
import copy
from logging import LogRecord, Filter
from datetime import datetime


class JSONFormatter(logging.Formatter):
    def format(self, record: LogRecord) -> str:
        message_dict = dict()
        message_dict.update({
            "level": record.levelname,
            "date": datetime.fromtimestamp(record.created).isoformat(),
            "module": f"{record.filename}:{record.lineno}",
            "process": record.process
        })
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
            message_dict["exc_info"] = {
                "type": str(record.exc_info[0]),
                "exception": str(record.exc_info[1]),
                "traceback": [
                    line.strip().replace('"', '\'').replace('\n', '')
                    for line in traceback.format_tb(record.exc_info[2])
                ]
            }
        if record.exc_text:
            message_dict["exc_text"] = record.exc_text

        return json.dumps(message_dict)


class ContextFilter(Filter):
    def filter(self, record: LogRecord) -> bool:
        thread = threading.current_thread()
        if hasattr(thread, "log_context"):
            record.context = thread.log_context
        return True


@contextlib.contextmanager
def logging_context(**kwargs):
    thread = threading.current_thread()
    old_log_context = {}
    if not hasattr(thread, "log_context"):
        thread.log_context = {}
    else:
        old_log_context = copy.deepcopy(thread.log_context)
    thread.log_context.update(kwargs)
    yield
    thread.log_context = old_log_context
