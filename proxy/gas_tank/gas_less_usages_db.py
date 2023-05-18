from typing import List, Iterator, Any

from ..common_neon.db.base_db_table import BaseDBTable
from ..common_neon.db.db_connect import DBConnection

from .gas_tank_types import GasLessUsage


class GasLessUsagesDB(BaseDBTable):
    def __init__(self, db: DBConnection):
        super().__init__(
            db,
            table_name='gas_less_usages',
            column_list=[
                'address', 'block_slot', 'neon_sig', 'nonce', 'to_addr', 'operator', 'neon_total_gas_usage'
            ],
            key_list=list()
        )

    def add_gas_less_usage_list(self, usage_list: Iterator[GasLessUsage]) -> None:
        row_list: List[List[Any]] = list()
        for usage in usage_list:
            row_list.append([
                str(usage.account),
                usage.block_slot, usage.neon_sig, usage.nonce, str(usage.to_addr),
                usage.operator, usage.neon_total_gas_usage
            ])

        self._insert_row_list(row_list)
