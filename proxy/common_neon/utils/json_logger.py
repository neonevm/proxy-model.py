import json
import logging
from logging import LogRecord
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
