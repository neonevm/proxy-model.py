import logging
import time

from typing import Tuple, List, Optional
from multiprocessing import Process

from ..common_neon.db.constats_db import ConstantsDB
from ..common_neon.db.db_connect import DBConnection
from ..common_neon.solana_not_empty_block import SolFirstBlockFinder, SolNotEmptyBlockFinder
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.config import Config, StartSlot
from ..common.logger import Logger
from ..common_neon.utils.json_logger import logging_context

from ..statistic.indexer_service import IndexerStatService

from .indexer import Indexer
from .indexer_db import IndexerDB
from .indexer_utils import get_config_start_slot


LOG = logging.getLogger(__name__)


class NeonIndexerApp:
    def __init__(self):
        Logger.setup()
        self._config = Config()

        self._db_conn: Optional[DBConnection] = None
        self._stat_service: Optional[IndexerStatService] = None

        self._first_slot = 0
        self._last_known_slot = 0
        self._start_slot = 0
        self._finalized_slot = 0

        self._reindex_ident = ''
        self._reindex_start_slot: Optional[int] = None
        self._reindex_stop_slot = 0

    def start(self):
        LOG.info(f'Running indexer with params: {self._config.as_dict()}')

        self._stat_service = IndexerStatService(self._config)
        self._stat_service.start()

        self._db_conn = DBConnection(self._config)
        constants_db = ConstantsDB(self._db_conn)

        self._drop_not_finalized_history()
        self._init_slot_range(constants_db)

        self._start_reindexing(constants_db)
        self._start_indexing()

    def _drop_not_finalized_history(self) -> None:
        db = IndexerDB.from_db(self._config, self._db_conn)
        db.drop_not_finalized_history()

    def _init_slot_range(self, constants_db: ConstantsDB) -> None:
        solana = SolInteractor(self._config)

        block_finder = SolFirstBlockFinder(solana)
        self._finalized_slot = finalized_slot = block_finder.finalized_slot
        self._first_slot = first_slot = block_finder.find_slot()
        self._last_known_slot = last_known_slot = constants_db.get(IndexerDB.base_min_used_slot_name, 0)

        if self._config.start_slot == StartSlot.Disable:
            self._reindex_stop_slot = self._get_reindex_stop_on_finalized_slot(constants_db)
            LOG.debug(f'{self._config.start_slot_name}={self._config.start_slot}, skip indexing...')
            return

        self._start_slot = get_config_start_slot(self._config, first_slot, finalized_slot, last_known_slot)
        # reindexing should stop on the start slot of indexing
        self._reindex_stop_slot = self._start_slot

    def _get_reindex_stop_on_finalized_slot(self, constants_db: ConstantsDB) -> int:
        """If it is the first start with disabling indexing,
        then collect information about blocks in the Solana
        """
        finalized_slot = constants_db.get(IndexerDB.finalized_slot_name, 0)
        if finalized_slot != 0:
            return finalized_slot

        constants_db[IndexerDB.finalized_slot_name] = self._finalized_slot
        return self._finalized_slot

    def _start_indexing(self) -> None:
        if self._config.start_slot == StartSlot.Disable:
            return self._empty_run()

        db = IndexerDB.from_range(self._config, self._db_conn, self._start_slot)
        indexer = Indexer(self._config, db)
        indexer.run()

    @staticmethod
    def _empty_run() -> None:
        while True:
            time.sleep(0.5)

    def _start_reindexing(self, constants_db: ConstantsDB) -> None:
        self._reindex_start_slot, self._reindex_ident = self._get_cfg_reindex_start_slot()

        if (self._reindex_start_slot is None) or (not self._config.reindex_thread_cnt):
            LOG.info(
                'Skip reindexing: '
                f'{self._config.reindex_start_slot_name}={self._reindex_ident}, '
                f'{self._config.reindex_thread_cnt_name}={self._config.reindex_thread_cnt}'
            )
            return

        db_list = self._load_exist_reindex_ranges(constants_db)
        if self._is_reindex_completed(constants_db, db_list):
            return

        self._add_new_reindex_ranges(db_list)
        self._launch_reindex_threads(db_list)

    def _is_reindex_completed(self, constants_db: ConstantsDB, db_list: List[IndexerDB]) -> bool:
        reindex_ident_name = 'reindex_ident'

        if self._reindex_ident == StartSlot.Continue:
            # every restart reindex slots from the last parsed slot to the current finalized slot
            constants_db[reindex_ident_name] = self._reindex_ident
            return False

        last_reindex_ident = constants_db.get(reindex_ident_name, '<NULL>')
        if (last_reindex_ident == self._reindex_ident) and (not len(db_list)):
            LOG.info(f'Reindexing {self._config.reindex_start_slot_name}={self._reindex_ident} was completed...')
            return True

        constants_db[reindex_ident_name] = self._reindex_ident
        return False

    def _load_exist_reindex_ranges(self, constants_db: ConstantsDB) -> List[IndexerDB]:
        db_list: List[IndexerDB] = list()

        for key in constants_db.keys():
            # For example: CONTINUE:213456789:starting_block_slot
            key_part_list = key.split(':')
            if len(key_part_list) != 3:
                continue

            reindex_ident, start_slot, key_name = key_part_list
            if key_name != IndexerDB.base_start_slot_name:
                continue

            db_key = ':'.join((reindex_ident, start_slot))
            db = IndexerDB.from_db(self._config, DBConnection(self._config), db_key)
            if self._reindex_ident != reindex_ident:
                LOG.info(f'Skip old REINDEX {db_key}')
                db.done()
            elif self._first_slot > db.stop_slot:
                LOG.info(
                    f'Skip lost REINDEX {db_key}: '
                    f'first slot ({self._first_slot}) > db.stop_slot ({db.stop_slot})'
                )
                db.done()
            else:
                LOG.info(f'Load REINDEX {db_key}')
                db_list.append(db)

        return db_list

    def _add_new_reindex_ranges(self, db_list: List[IndexerDB]) -> None:
        new_db_list = self._build_new_reindex_ranges(db_list)
        new_db_list = self._try_extend_last_db(db_list, new_db_list)
        db_list.extend(new_db_list)

    def _build_new_reindex_ranges(self, db_list: List[IndexerDB]) -> List[IndexerDB]:
        """Reindex slots between the reindexing start slot and indexing start slot.
        Check that the number of ranges is not exceeded.
        """

        solana = SolInteractor(self._config)

        start_slot = max(self._reindex_start_slot, self._first_slot)
        if len(db_list):
            last_old_db = max(db_list, key=lambda x: x.start_slot)
            start_slot = max(last_old_db.stop_slot, start_slot)

        total_len = self._reindex_stop_slot - start_slot + 1
        avail_cnt = max(1, self._config.reindex_max_range_cnt - len(db_list))
        need_cnt = int(total_len / self._config.reindex_range_len) + 1
        avail_cnt = min(avail_cnt, need_cnt)
        range_len = int(total_len / avail_cnt) + 1

        new_db_list: List[IndexerDB] = list()
        while start_slot < self._reindex_stop_slot:
            # For example: CONTINUE:213456789
            ident = ':'.join([self._reindex_ident, str(start_slot)])
            stop_slot = min(start_slot + range_len, self._reindex_stop_slot)
            start_slot = SolNotEmptyBlockFinder(solana, start_slot, self._finalized_slot).find_slot()
            db = IndexerDB.from_range(self._config, DBConnection(self._config), start_slot, ident, stop_slot)
            new_db_list.append(db)
            start_slot = stop_slot

        return new_db_list

    def _try_extend_last_db(self, db_list: List[IndexerDB], new_db_list: List[IndexerDB]) -> List[IndexerDB]:
        """If it is the fast restart, the number of blocks between restarts is small.
        So here we are trying to merge the last previous range with the new first range.
        """
        if (not len(db_list)) or (not len(new_db_list)):
            return new_db_list

        first_new_db = min(new_db_list, key=lambda x: x.start_slot)
        last_old_db = max(db_list, key=lambda x: x.start_slot)
        if first_new_db.start_slot - last_old_db.stop_slot > self._config.reindex_range_len:
            return new_db_list

        last_old_db.set_stop_slot(first_new_db.stop_slot)
        return new_db_list[1:]

    def _get_cfg_reindex_start_slot(self) -> Tuple[Optional[int], str]:
        """ Valid variants:
        REINDEXER_START_SLOT=CONTINUE, START_SLOT=LATEST
        REINDEXER_START_SLOT=10123456, START_SLOT=CONTINUE
        REINDEXER_START_SLOT=10123456, START_SLOT=LATEST
        REINDEXER_START_SLOT=10123456, START_SLOT=100
        """
        reindex_ident = self._config.reindex_start_slot

        if isinstance(reindex_ident, int):
            if reindex_ident >= self._finalized_slot:
                LOG.error(f'{self._config.reindex_start_slot_name}={reindex_ident} is too big, skip reindexing...')
                return None, ''

            # start from the slot which Solana knows
            start_slot = reindex_ident
            reindex_ident = str(start_slot)

            LOG.info(
                f'{self._config.reindex_start_slot_name}={reindex_ident}: '
                f'started reindexing from the slot: {start_slot}'
            )
            return start_slot, reindex_ident

        elif reindex_ident == StartSlot.Disable:
            return None, ''

        elif reindex_ident == StartSlot.Continue:
            if self._config.start_slot not in (StartSlot.Latest, StartSlot.Disable):
                LOG.error(
                    f'Wrong value {self._config.reindex_start_slot_name}={StartSlot.Continue}, '
                    f'it is valid only for {self._config.start_slot_name}=({StartSlot.Latest, StartSlot.Disable}): '
                    f'forced to disable {self._config.reindex_start_slot_name}'
                )
                return None, ''

            # self._last_known_slot = 0 - it happens if it is the first start
            # and the ReIndexer cannot start from the slot which Solana doesn't know
            start_slot = max(self._first_slot, (self._last_known_slot or self._finalized_slot))

            LOG.info(
                f'{self._config.reindex_start_slot_name}={StartSlot.Continue}: '
                f'started reindexing from the slot: {start_slot}'
            )
            return start_slot, reindex_ident

        LOG.error(f'{self._config.reindex_start_slot_name}={reindex_ident}: wrong value, skip reindexing...')
        return None, ''

    def _launch_reindex_threads(self, db_list: List[IndexerDB]) -> None:
        """Split the DB list so that the first starting slots are reindexed first.

        For example:
        self._cfg.reindex_thread_cnt = 2
        I -> IndexerDB
        S -> start_slot
        I(S=1) -> IndexerDB(start_slot=1)

        [I(S=1000), I(S=10), I(S=11), I(S=12), I(S=102)]

        ReIndexer(0): [I(S=10), I(S=12),  I(S=1000)]
        ReIndexer(1): [I(S=11), I(S=102)]
        """
        db_list = sorted(db_list, key=lambda x: x.start_slot, reverse=True)
        reindex_db_list_list: List[List[IndexerDB]] = [list() for _ in range(self._config.reindex_thread_cnt)]

        idx = 0
        while len(db_list) > 0:
            db = db_list.pop()
            reindex_db_list_list[idx].append(db)
            idx += 1
            if idx >= self._config.reindex_thread_cnt:
                idx = 0

        for idx in range(self._config.reindex_thread_cnt):
            reindex_db_list = reindex_db_list_list[idx]
            if not len(reindex_db_list):
                break

            reindexer = ReIndexer(idx, self._config, reindex_db_list)
            reindexer.start()


class ReIndexer:
    def __init__(self, idx: int, cfg: Config, db_list: List[IndexerDB]):
        self._idx = idx
        self._cfg = cfg
        self._db_list = db_list

    def start(self) -> None:
        """Python has GIL... It can be resolved with separate processes"""
        process = Process(target=self._run)
        process.start()

    def _run(self) -> None:
        """Under the hood it runs the Indexer but in a limited range of slots."""
        LOG.info(f'Start ReIndexer({self._idx})')
        for db in self._db_list:
            with logging_context(reindex_ident=db.reindex_ident):
                LOG.info(
                    f'Start to reindex the range {db.start_slot}(->{db.min_used_slot}):{db.stop_slot} '
                    f'on the ReIndexer({self._idx})',
                )

                indexer = Indexer(self._cfg, db)
                indexer.run()
                db.done()

                LOG.info(
                    f'Done reindex the range {db.start_slot}:{db.stop_slot} '
                    f'on the ReIndexer({self._idx})'
                )
