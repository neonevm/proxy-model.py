import bisect
from typing import TypeVar, Generic, Sequence, List, Callable, Iterator, Union, Optional


SortedQueueItem = TypeVar('SortedQueueItem')
SortedQueueLtKey = TypeVar('SortedQueueLtKey')
SortedQueueEqKey = TypeVar('SortedQueueEqKey')


class SortedQueue(Generic[SortedQueueItem, SortedQueueLtKey, SortedQueueEqKey]):
    class _SortedQueueImpl(Sequence[SortedQueueItem]):
        def __init__(self, lt_key_func: Callable[[SortedQueueItem], SortedQueueLtKey]):
            self.queue: List[SortedQueue] = []
            self.lt_key_func = lt_key_func

        def __getitem__(self, index: int) -> SortedQueueLtKey:
            return self.lt_key_func(self.queue[index])

        def __len__(self) -> int:
            return len(self.queue)

        def bisect_left(self, item: SortedQueueItem) -> int:
            return bisect.bisect_left(self, self.lt_key_func(item))

        def __iter__(self) -> Iterator[SortedQueueItem]:
            return iter(self.queue)

    def __init__(self, lt_key_func: Callable[[SortedQueueItem], SortedQueueLtKey],
                 eq_key_func: Callable[[SortedQueueItem], SortedQueueEqKey]):
        self._impl = self._SortedQueueImpl(lt_key_func)
        self._eq_key_func = eq_key_func

    def __getitem__(self, index: int) -> SortedQueueItem:
        return self._impl.queue[index]

    def extract_list_from(self, index: int) -> List[SortedQueueItem]:
        extracted_list = self._impl.queue[index:]
        self._impl.queue = self._impl.queue[:index]
        return extracted_list

    def __contains__(self, item: SortedQueueItem) -> bool:
        return self.find(item) is not None

    def __len__(self) -> int:
        return len(self._impl)

    def add(self, item: SortedQueueItem) -> None:
        assert self.find(item) is None, 'item is already in the queue'
        pos = self._impl.bisect_left(item)
        self._impl.queue.insert(pos, item)

    def find(self, item: SortedQueueItem) -> Optional[int]:
        start_pos = self._impl.bisect_left(item)
        for index in range(start_pos, len(self)):
            if self._impl.lt_key_func(item) != self._impl.lt_key_func(self._impl.queue[index]):
                break
            if self._eq_key_func(self._impl.queue[index]) == self._eq_key_func(item):
                return index
        return None

    def pop(self, item_or_index: Union[int, SortedQueueItem]) -> SortedQueueItem:
        assert len(self) > 0, 'queue is empty'

        index = item_or_index if isinstance(item_or_index, int) else self.find(item_or_index)
        assert index is not None, 'item is absent in the queue'

        return self._impl.queue.pop(index)

    def remove_if(self, predict: Callable[[SortedQueueItem], bool]) -> None:
        self._impl.queue = [item for item in self._impl.queue if not predict(item)]

    def clear(self) -> None:
        self._impl.queue.clear()

    def __iter__(self):
        return iter(self._impl)

