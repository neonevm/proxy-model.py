from __future__ import annotations

import statistics
import logging

from typing import Dict, Union, List

from .config import Config


LOG = logging.getLogger(__name__)


class MetricsLogger:
    def __init__(self, config: Config):
        self._config = config
        self._counter: int = 0
        self._item_list_dict: Dict[str, List[Union[int, float]]] = {}

    def _reset(self):
        self._counter = 0
        self._item_list_dict.clear()

    def is_print_time(self) -> bool:
        return (self._counter + 1) % self._config.metrics_log_skip_cnt == 0

    def print(self, list_value_dict: Dict[str, Union[int, float]],
              latest_value_dict: Dict[str, int]):
        for key, value in list_value_dict.items():
            metric_list = self._item_list_dict.setdefault(key, [])
            metric_list.append(value)

        is_print_time = self.is_print_time()
        self._counter += 1
        if not is_print_time:
            return

        msg = ''
        for key, value_list in self._item_list_dict.items():
            msg += f' {key} avg: {statistics.mean(value_list):.2f}'
            msg += f' min: {min(value_list):.2f}'
            msg += f' max: {max(value_list):.2f};'

        for key, value in latest_value_dict.items():
            msg += f' {key}: {value};'

        LOG.debug(msg)
        self._reset()
