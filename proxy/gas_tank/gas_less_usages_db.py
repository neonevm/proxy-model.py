from typing import List, Iterator, Any

from ..indexer.base_db import BaseDB
from .gas_tank_types import GasLessUsage


class GasLessUsagesDB(BaseDB):
    def __init__(self):
        super().__init__(
            table_name='gas_less_usages',
            column_list=[
                'address', 'block_slot', 'neon_sig', 'nonce', 'to_addr', 'operator', 'neon_total_gas_usage'
            ]
        )

    def add_gas_less_usage_list(self, cursor: BaseDB.Cursor, usage_list: Iterator[GasLessUsage]) -> None:
        row_list: List[List[Any]] = list()
        for usage in usage_list:
            row_list.append([
                str(usage.account),
                usage.block_slot, usage.neon_sig, usage.nonce, str(usage.to_addr),
                usage.operator, usage.neon_total_gas_usage
            ])

        self._insert_batch(cursor, row_list)
