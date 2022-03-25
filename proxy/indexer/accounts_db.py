from dataclasses import astuple, dataclass
from ..indexer.base_db import BaseDB, DBQuery
from ..common_neon.utils import str_fmt_object


@dataclass
class NeonAccountInfo:
    neon_address: str = None
    pda_address: str = None
    code_address: str = None
    slot: int = 0
    code: str = None
    sol_sign: str = None

    def __init__(self, neon_address: str = None, pda_address: str = None, code_address: str = None, slot: int = 0, code: str = None, sol_sign: str = None):
        self.neon_address = neon_address
        self.pda_address = pda_address
        self.code_address = code_address
        self.slot = slot
        self.code = code
        self.sol_sign = sol_sign

    def __str__(self):
        return str_fmt_object(self)

    def __iter__(self):
        return iter(astuple(self))


class NeonAccountDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self, 'neon_accounts')

    def set_acc_by_request(self, neon_account: NeonAccountInfo):
        with self._conn.cursor() as cursor:
            cursor.execute(f'''
                INSERT INTO neon_accounts (neon_address, pda_address, code_address, slot, code, sol_sign)
                VALUES(%s, %s, %s, %s, %s, %s)
                ON CONFLICT (pda_address, code_address) DO UPDATE
                SET
                    code=EXCLUDED.code
                ;
                ''',
                tuple(neon_account))

    def set_acc_indexer(self, neon_account: NeonAccountInfo):
        neon_account = self.fill_neon_address_if_missing(neon_account)
        if not neon_account.neon_address:
            return
        with self._conn.cursor() as cursor:
            cursor.execute(f'''
                INSERT INTO neon_accounts (neon_address, pda_address, code_address, slot,  code, sol_sign)
                VALUES(%s, %s, %s, %s, %s, %s)
                ON CONFLICT (pda_address, code_address) DO UPDATE
                SET
                    slot=EXCLUDED.slot
                ;
                ''',
                tuple(neon_account))

    def fill_neon_address_if_missing(self, neon_account: NeonAccountInfo) -> NeonAccountInfo:
        if not neon_account.neon_address:
            value = self.get_account_info_by_pda_address(neon_account.pda_address)
            if not value.neon_address:
                self.error(f"Not found account for pda_address: {neon_account.pda_address}")
                return neon_account
            neon_account.neon_address = value.neon_address
        return neon_account

    def _acc_from_value(self, value) -> NeonAccountInfo:
        self.debug(f"accounts db returned {value}")

        if not value:
            return NeonAccountInfo()

        return NeonAccountInfo(
            neon_address=value[0],
            pda_address=value[1],
            code_address=value[2],
            slot=value[3],
            code=value[4],
            sol_sign=value[5]
        )

    def get_account_info_by_neon_address(self, neon_address) -> NeonAccountInfo:
        return self._acc_from_value(
            self._fetchone(DBQuery(
                column_list=['neon_address', 'pda_address', 'code_address', 'slot', 'code', 'sol_sign'],
                key_list=[('neon_address', neon_address)],
                order_list=['slot desc']
            ))
        )

    def get_account_info_by_pda_address(self, pda_address) -> NeonAccountInfo:
        return self._acc_from_value(
            self._fetchone(DBQuery(
                column_list=['neon_address', 'pda_address', 'code_address', 'slot', 'code', 'sol_sign'],
                key_list=[('pda_address', pda_address)],
                order_list=['slot desc']
            ))
        )
