import math
import logging

from dataclasses import dataclass
from typing import Optional, List, Any, Tuple

from ..common_neon.solana_block import SolBlockInfo
from ..common_neon.db.base_db_table import BaseDBTable
from ..common_neon.db.db_connect import DBConnection
from ..common_neon.solana_tx import SolCommit
from ..common_neon.constants import ONE_BLOCK_SEC

from .indexed_objects import NeonIndexedBlockInfo


LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class SolBlockSlotRange:
    earliest_slot: int
    finalized_slot: int
    latest_slot: int


class SolBlocksDB(BaseDBTable):
    def __init__(self, db: DBConnection):
        super().__init__(
            db,
            table_name='solana_blocks',
            column_list=[
                'block_slot', 'block_hash', 'block_time', 'parent_block_slot', 'is_finalized', 'is_active'
            ],
            key_list=['block_slot']
        )

    @staticmethod
    def _generate_fake_block_hash(block_slot: int) -> str:
        if block_slot < 0:
            return '0x' + '0' * 64

        hex_num = hex(block_slot)[2:]
        num_len = len(hex_num)
        hex_num = '00' + hex_num.rjust(((num_len >> 1) + (num_len % 2)) << 1, '0')
        return '0x' + hex_num.rjust(64, 'f')

    def _check_block_hash(self, block_slot: int, block_hash: Optional[str]) -> str:
        return block_hash or self._generate_fake_block_hash(block_slot)

    def _generate_block_time(self, block_slot: int) -> Optional[int]:
        # Search the nearest block before requested block
        request = f'''
            (SELECT block_slot AS b_block_slot,
                    block_time AS b_block_time,
                    NULL AS n_block_slot,
                    NULL AS n_block_time
               FROM {self._table_name}
              WHERE block_slot <= %s
           ORDER BY block_slot DESC LIMIT 1)

           UNION DISTINCT

           (SELECT NULL AS b_block_slot,
                   NULL AS b_block_time,
                   block_slot AS n_block_slot,
                   block_time AS n_block_time
              FROM {self._table_name}
             WHERE block_slot >= %s
          ORDER BY block_slot LIMIT 1)
        '''
        value_list = self._fetch_one(request, (block_slot, block_slot,))
        if not len(value_list):
            LOG.warning(f'Failed to get nearest blocks for block {block_slot}')
            return None

        nearest_block_slot = value_list[0]
        if nearest_block_slot is not None:
            nearest_block_time = value_list[1]
            return nearest_block_time + math.ceil((block_slot - nearest_block_slot) * ONE_BLOCK_SEC)

        nearest_block_slot = value_list[2]
        nearest_block_time = value_list[3]
        return nearest_block_time - math.ceil((nearest_block_slot - block_slot) * ONE_BLOCK_SEC)

    @staticmethod
    def _get_fake_block_slot(hash_number: str) -> Optional[int]:
        hash_number = hash_number[2:].lstrip('f')
        if len(hash_number) > 12 or hash_number[:2] != '00':
            return None
        hex_number = hash_number.lstrip('0')
        if not hex_number:
            return 0
        return int(hex_number, 16)

    def _generate_fake_block(self, block_slot: Optional[int], slot_range: SolBlockSlotRange) -> SolBlockInfo:
        if block_slot is None:
            return SolBlockInfo(block_slot=0)

        block_time = self._generate_block_time(block_slot)
        if not block_time:
            return SolBlockInfo(block_slot=block_slot)

        is_finalized = block_slot <= slot_range.finalized_slot
        sol_commit = SolCommit.Finalized if is_finalized else SolCommit.Confirmed

        return SolBlockInfo(
            block_slot=block_slot,
            sol_commit=sol_commit,
            is_finalized=is_finalized,
            block_hash=self._generate_fake_block_hash(block_slot),
            block_time=block_time,
            parent_block_hash=self._generate_fake_block_hash(block_slot - 1),
        )

    def _block_from_value(
        self, block_slot: Optional[int],
        slot_range: SolBlockSlotRange,
        value_list: List[Any]
    ) -> SolBlockInfo:
        if not len(value_list):
            return self._generate_fake_block(block_slot, slot_range)

        if block_slot is None:
            block_slot = self._get_column_value('block_slot', value_list)

        block_time = self._get_column_value('block_time', value_list)
        if not block_time:
            block_time = self._generate_block_time(block_slot)

        is_finalized = self._get_column_value('is_finalized', value_list)
        sol_commit = SolCommit.Finalized if is_finalized else SolCommit.Confirmed

        return SolBlockInfo(
            block_slot=block_slot,
            sol_commit=sol_commit,
            is_finalized=is_finalized,
            block_hash=self._check_block_hash(block_slot, self._get_column_value('block_hash', value_list)),
            block_time=block_time,
            parent_block_hash=self._check_block_hash(block_slot - 1, value_list[6])
        )

    def get_block_by_slot(self, block_slot: int, slot_range: SolBlockSlotRange) -> SolBlockInfo:
        if block_slot > slot_range.latest_slot:
            return SolBlockInfo(block_slot=block_slot)
        elif block_slot < slot_range.earliest_slot:
            return self._generate_fake_block(block_slot, slot_range)

        request = f'''
                (SELECT {', '.join(['a.' + c for c in self._column_list])},
                        b.block_hash AS parent_block_hash
                   FROM {self._table_name} AS a
        LEFT OUTER JOIN {self._table_name} AS b
                     ON b.block_slot = %s
                    AND b.is_active = True
                  WHERE a.block_slot = %s
                    AND a.is_active = True
                  LIMIT 1)

         UNION DISTINCT

                (SELECT {', '.join(['a.' + c for c in self._column_list])},
                        b.block_hash AS parent_block_hash
                   FROM {self._table_name} AS b
        LEFT OUTER JOIN {self._table_name} AS a
                     ON a.block_slot = %s
                    AND a.is_active = True
                  WHERE b.block_slot = %s
                    AND b.is_active = True
                  LIMIT 1)
        '''

        value_list = self._fetch_one(request, (block_slot - 1, block_slot, block_slot, block_slot - 1))
        return self._block_from_value(block_slot, slot_range, value_list)

    def get_block_by_hash(self, block_hash: str, slot_range: SolBlockSlotRange) -> SolBlockInfo:
        fake_block_slot = self._get_fake_block_slot(block_hash)
        if fake_block_slot is not None:
            block = self.get_block_by_slot(fake_block_slot, slot_range)
            block.set_block_hash(block_hash)  # it can be a request from an uncle history branch
            return block

        request = f'''
                 SELECT {', '.join(['a.' + c for c in self._column_list])},
                        b.block_hash AS parent_block_hash

                   FROM {self._table_name} AS a
        FULL OUTER JOIN {self._blocks_table_name} AS b
                     ON b.block_slot = a.block_slot - 1
                    AND a.is_active = True
                    AND b.is_active = True
                  WHERE a.block_hash = %s
        '''
        value_list = self._fetch_one(request, (block_hash,))
        return self._block_from_value(None, slot_range, value_list)

    def set_block_list(self, neon_block_queue: List[NeonIndexedBlockInfo]) -> None:
        row_list: List[List[Any]] = list()

        for neon_block in neon_block_queue:
            block = neon_block.sol_block
            row_list.append([
                block.block_slot,
                block.block_hash,
                block.block_time,
                block.parent_block_slot,
                block.is_finalized,
                block.is_finalized
            ])
        self._insert_row_list(row_list)

    def finalize_block_list(self, from_slot: int, to_slot: int, slot_list: Tuple[int, ...]) -> None:
        request = f'''
            UPDATE {self._table_name}
               SET is_finalized = True,
                   is_active = True
             WHERE block_slot IN %s
        '''
        self._update_row(request, (slot_list,))

        request = f'''
            DELETE FROM {self._table_name}
                  WHERE block_slot > %s
                    AND block_slot <= %s
                    AND block_slot NOT IN %s
        '''
        self._update_row(request, (from_slot, to_slot, slot_list))

    def activate_block_list(self, from_slot: int, slot_list: Tuple[int, ...]) -> None:
        request = f'''
            UPDATE {self._table_name}
               SET is_active = False
             WHERE block_slot > %s
        '''
        self._update_row(request, (from_slot,))

        request = f'''
            UPDATE {self._table_name}
               SET is_active = True
             WHERE block_slot IN %s
        '''
        self._update_row(request, (slot_list,))
