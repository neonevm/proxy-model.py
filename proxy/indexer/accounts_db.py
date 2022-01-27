from .utils import BaseDB, str_fmt_object
from .pg_common import decode


class NeonAccountInfo:
    def __init__(self, neon_account: str, pda_account: str, code_account: str, slot: int, code: str = None):
        self.neon_account = neon_account
        self.pda_account = pda_account
        self.code_account = code_account
        self.slot = slot
        self.code = code

    def __str__(self):
        return str_fmt_object(self)


class NeonAccountDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self)

    def _create_table_sql(self) -> str:
        self._table_name = 'neon_accounts'
        return f"""
            CREATE TABLE IF NOT EXISTS {self._table_name} (
                neon_account CHAR(42),
                pda_account CHAR(50) UNIQUE,
                code_account CHAR(50),
                slot BIGINT,
                code TEXT
            );"""

    def set_acc(self, neon_account: str, pda_account: str, code_account: str, slot: int, code: str = None):
        with self._conn.cursor() as cursor:
            cursor.execute(f'''
                INSERT INTO {self._table_name}(neon_account, pda_account, code_account, slot, code)
                VALUES(%s, %s, %s, %s, %s)
                ON CONFLICT (pda_account) DO UPDATE
                SET
                    code_account=EXCLUDED.code_account,
                    slot=EXCLUDED.slot,
                    code=EXCLUDED.code
                WHERE
                    ({self._table_name}.slot<EXCLUDED.slot)
                    OR
                    ({self._table_name}.code=NULL AND EXCLUDED.code<>NULL)
                ;
                ''',
                (neon_account, pda_account, code_account, slot, code))

    def _acc_from_value(self, value) -> NeonAccountInfo:
        if not value:
            return None

        return NeonAccountInfo(
            neon_account=value[0],
            pda_account=value[1],
            code_account=value[2],
            slot=value[3],
            code=decode(value[4])
        )

    def get_account_info(self, account) -> NeonAccountInfo:
        return self._acc_from_value(
            self._fetchone(['neon_account', 'pda_account', 'code_account', 'slot', 'code'],
                           [('neon_account', account)],
                           ['slot desc']))
