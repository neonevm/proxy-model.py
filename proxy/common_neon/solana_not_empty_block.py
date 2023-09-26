import typing
import bisect
import logging

from .solana_interactor import SolInteractor
from .solana_tx import SolCommit


LOG = logging.getLogger(__name__)


class SolNotEmptyBlockFinder(typing.Sequence[bool]):
    def __init__(self, solana: SolInteractor, start_slot: int, stop_slot: typing.Optional[int] = None):
        self._solana = solana
        self._start_slot = start_slot
        self._stop_slot = stop_slot or self._solana.get_finalized_slot()
        self._hdr = f'trying to find a not-empty slot in the range {self._start_slot, self._stop_slot}'

    @property
    def finalized_slot(self) -> int:
        return self._stop_slot

    def __len__(self) -> int:
        return self._stop_slot - self._start_slot

    def __getitem__(self, offset: int) -> bool:
        base_slot, slot_list = self._get_slot_range(offset)
        if not len(slot_list):
            LOG.debug(f'{self._hdr}, SKIP the slot {base_slot}, because NO blocks...')
            return False

        slot = slot_list[0]
        result = not self._solana.get_block_info(slot).is_empty()
        if result:
            LOG.debug(f'{self._hdr}, FOUND the base slot {base_slot}, with the block at the slot {slot}...')
        else:
            LOG.debug(f'{self._hdr}, SKIP the base slot {base_slot}, because NO block at the slot {slot}...')
        return result

    def _get_slot_range(self, offset: int) -> typing.Tuple[int, typing.List[int]]:
        base_slot = self._start_slot + offset
        stop_slot = min(self._stop_slot, base_slot + 1024)
        return base_slot, self._solana.get_block_slot_list(base_slot, stop_slot, SolCommit.Finalized)

    def find_slot(self) -> int:
        if self._start_slot >= self._stop_slot:
            LOG.warning(
                f'{self._hdr}, the start slot {self._start_slot} is bigger or equal to the finalized slot, '
                f'FORCE to use finalized slot {self._stop_slot}'
            )
            return self._stop_slot

        base_slot, slot_list = self._get_slot_range(0)
        if len(slot_list) and (not self._solana.get_block_info(slot_list[0]).is_empty()):
            slot = slot_list[0]
            LOG.debug(f'{self._hdr}, FOUND the slot {slot} with the block')
            return slot

        # resolve the bad situation, when the Solana node has list of blocks, by they are empty
        offset = bisect.bisect_left(self, True)
        base_slot, slot_list = self._get_slot_range(offset)
        for slot in slot_list:
            if not self._solana.get_block_info(slot).is_empty():
                LOG.debug(f'{self._hdr}, FOUND the slot {slot} with the block')
                return slot

        LOG.warning(f'{self._hdr}, FORCE to use the finalized slot {self._stop_slot}')
        return self._stop_slot


class SolFirstBlockFinder(SolNotEmptyBlockFinder):
    def __init__(self, solana: SolInteractor):
        first_slot = solana.get_first_available_slot()
        if first_slot > 0:
            first_slot += 512

        super().__init__(solana, first_slot)
