from typing import Iterator, Any, List, Union

from .gas_tank_types import GasLessPermit

from ..common_neon.address import NeonAddress
from ..common_neon.db.base_db_table import BaseDBTable
from ..common_neon.db.db_connect import DBConnection


class GasLessAccountsDB(BaseDBTable):
    def __init__(self, db: DBConnection):
        super().__init__(
            db,
            table_name='gas_less_accounts',
            column_list=[
                'address', 'contract', 'nonce', 'block_slot', 'neon_sig'
            ],
            key_list=['address', 'contract', 'nonce']
        )

    def has_gas_less_tx_permit(self, address: Union[str, NeonAddress]) -> bool:
        request = f'''
            SELECT a.address
              FROM {self._table_name} AS a
             WHERE a.address = %s AND a.nonce = 0 AND a.contract IS NULL
             LIMIT 1
        '''

        if isinstance(address, NeonAddress):
            address = address.address

        value_list = self._fetch_one(request, (address,))
        return len(value_list) > 0

    def add_gas_less_permit_list(self, permit_list: Iterator[GasLessPermit]) -> None:
        row_list: List[List[Any]] = list()
        for permit in permit_list:
            account = permit.account.address
            contract = permit.contract.address if permit.contract is not None else None

            row_list.append([
                account, contract, permit.nonce, permit.block_slot, permit.neon_sig
            ])

        self._insert_row_list(row_list)
