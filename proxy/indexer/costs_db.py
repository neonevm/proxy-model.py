from typing import List

from ..indexer.utils import CostInfo
from ..indexer.base_db import BaseDB


class CostsDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self)

    def _create_table_sql(self) -> str:
        self._table_name = 'solana_neon_transactions_costs'
        return f"""
            CREATE TABLE IF NOT EXISTS {self._table_name} (
                sol_sign CHAR(88) UNIQUE,
                operator VARCHAR(50),

                neon_steps INT,
                bpf_instructions INT,

                sol_cost BIGINT,
                token_income BIGINT
            );"""

    def add_costs(self, tx_costs: List[CostInfo]):
        rows = []
        for cost_info in tx_costs:
            rows.append((
                cost_info.sign,
                cost_info.operator,

                cost_info.step,
                cost_info.bpf,

                cost_info.sol_spent,
                cost_info.token_income
            ))

        with self._conn.cursor() as cursor:
            cursor.executemany(f'''
                INSERT INTO {self._table_name}
                (sol_sign, operator, neon_steps, bpf_instructions, sol_cost, token_income)
                VALUES(%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING''',
                rows)
