import bisect
from typing import List, Dict, Set, Optional, Union, Callable, TypeVar, Sequence, Generic, cast

from logged_groups import logged_group, logging_context

from ..common_neon.eth_proto import Trx as NeonTx

from .mempool_api import MPTxRequest, MPTxSendResult, MPTxSendResultCode, MPSenderTxCntResult


SortedQueueItem = TypeVar('SortedQueueItem')
SortedQueueLtKey = TypeVar('SortedQueueLtKey')
SortedQueueEqKey = TypeVar('SortedQueueEqKey')


class SortedQueue(Generic[SortedQueueItem, SortedQueueLtKey, SortedQueueEqKey]):
    class _SortedQueueImpl(Sequence[SortedQueueItem]):
        def __init__(self, lt_key_func: Callable[[SortedQueueItem], SortedQueueLtKey]):
            self.queue: List[SortedQueue] = []
            self._lt_key_func = lt_key_func

        def __getitem__(self, index: int) -> SortedQueueLtKey:
            return self._lt_key_func(self.queue[index])

        def __len__(self) -> int:
            return len(self.queue)

        def bisect_left(self, item: SortedQueueItem) -> int:
            return bisect.bisect_left(self, self._lt_key_func(item))

    def __init__(self, lt_key_func: Callable[[SortedQueueItem], SortedQueueLtKey],
                 eq_key_func: Callable[[SortedQueueItem], SortedQueueEqKey]):
        self._impl = self._SortedQueueImpl(lt_key_func)
        self._eq_key_func = eq_key_func

    def __getitem__(self, index: int) -> SortedQueueItem:
        return self._impl.queue[index]

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
            if self._eq_key_func(self._impl.queue[index]) == self._eq_key_func(item):
                return index
        return None

    def pop(self, item_or_index: Union[int, SortedQueueItem]) -> SortedQueueItem:
        assert len(self) > 0, 'queue is empty'

        index = item_or_index if isinstance(item_or_index, int) else self.find(item_or_index)
        assert index is not None, 'item is absent in the queue'

        return self._impl.queue.pop(index)


@logged_group("neon.MemPool")
class MPTxRequestDict:
    def __init__(self) -> None:
        self._tx_hash_dict: Dict[str, MPTxRequest] = {}
        self._tx_sender_nonce_dict: Dict[str, MPTxRequest] = {}
        self._tx_gas_price_queue = SortedQueue[MPTxRequest, int, str](
            lt_key_func=lambda a: -a.gas_price,
            eq_key_func=lambda a: a.signature
        )

    def __len__(self) -> int:
        return len(self._tx_hash_dict)

    @staticmethod
    def _sender_nonce(tx: MPTxRequest) -> str:
        return f'{tx.sender_address}:{tx.nonce}'

    def add(self, tx: MPTxRequest) -> None:
        sender_nonce = self._sender_nonce(tx)
        assert tx.signature not in self._tx_hash_dict, f'Tx {tx.signature} is already in the dictionary'
        assert sender_nonce not in self._tx_sender_nonce_dict, f'Tx {sender_nonce} is already in the dictionary'

        self._tx_hash_dict[tx.signature] = tx
        self._tx_sender_nonce_dict[sender_nonce] = tx
        self._tx_gas_price_queue.add(tx)
        assert len(self._tx_hash_dict) == len(self._tx_sender_nonce_dict) >= len(self._tx_gas_price_queue)

    def pop(self, tx: MPTxRequest) -> MPTxRequest:
        assert tx.signature in self._tx_hash_dict, f'Tx {tx.signature} is absent in the dictionary'

        sender_nonce = self._sender_nonce(tx)
        assert sender_nonce in self._tx_sender_nonce_dict, f'Tx {sender_nonce} is absent in the dictionary'

        pos = self._tx_gas_price_queue.find(tx)
        # tx was removed from the gas price queue on processing
        if pos is not None:
            self._tx_gas_price_queue.pop(pos)

        self._tx_sender_nonce_dict.pop(sender_nonce)
        return self._tx_hash_dict.pop(tx.signature, None)

    def get_tx_by_hash(self, tx_hash: str) -> Optional[MPTxRequest]:
        return self._tx_hash_dict.get(tx_hash, None)

    def get_tx_by_sender_nonce(self, tx: MPTxRequest) -> Optional[MPTxRequest]:
        return self._tx_sender_nonce_dict.get(self._sender_nonce(tx), None)

    def process_tx(self, tx: MPTxRequest) -> None:
        self._tx_gas_price_queue.pop(tx)

    def cancel_process_tx(self, tx: MPTxRequest) -> None:
        self._tx_gas_price_queue.add(tx)

    def get_tx_by_lower_gas_price(self) -> Optional[MPTxRequest]:
        return self._tx_gas_price_queue[-1] if len(self._tx_gas_price_queue) > 0 else None


@logged_group("neon.MemPool")
class MPSenderTxPool:
    _top_index = -1
    _bottom_index = 0

    def __init__(self, sender_address: Optional[str] = None) -> None:
        self.sender_address = sender_address
        self._state_tx_cnt = 0
        self._processing_tx: Optional[MPTxRequest] = None
        self._tx_nonce_queue = SortedQueue[MPTxRequest, int, str](
            lt_key_func=lambda a: -a.nonce,
            eq_key_func=lambda a: a.signature
        )

    def __len__(self) -> int:
        return len(self._tx_nonce_queue)

    def add_tx(self, tx: MPTxRequest) -> None:
        assert self._state_tx_cnt <= tx.nonce, f'Tx {tx.signature} has nonce {tx.nonce} less than {self._state_tx_cnt}'
        self._tx_nonce_queue.add(tx)

    def get_top_tx(self) -> Optional[MPTxRequest]:
        return self._tx_nonce_queue[self._top_index] if not self.is_empty() else None

    def is_top_tx(self, tx: MPTxRequest) -> bool:
        top_tx = self.get_top_tx()
        return top_tx.signature == tx.signature if top_tx is not None else False

    def process_tx(self) -> MPTxRequest:
        assert not self.is_processing()

        self._processing_tx = self.get_top_tx()
        return self._processing_tx

    def get_last_nonce(self) -> Optional[int]:
        return self._tx_nonce_queue[self._bottom_index] if not self.is_empty() else None

    def get_gas_price(self) -> int:
        tx = self.get_top_tx()
        return tx.gas_price if tx is not None else 0

    def is_empty(self) -> bool:
        return len(self) == 0

    def is_processing(self) -> bool:
        return self._processing_tx is not None

    def get_state_tx_cnt(self) -> int:
        if self.is_processing():
            assert self._state_tx_cnt == self._processing_tx.nonce
            return self._processing_tx.nonce + 1
        return self._state_tx_cnt

    def set_state_tx_cnt(self, value: int) -> None:
        assert not self.is_empty()
        assert self._state_tx_cnt <= value
        assert self.get_top_tx().nonce >= value

        self._state_tx_cnt = value

    def is_paused(self) -> bool:
        assert not self.is_empty()
        return self._state_tx_cnt != self.get_top_tx().nonce

    def _validate_processing_tx(self, tx: MPTxRequest) -> None:
        assert not self.is_empty(), f'no transactions in the sender tx pool {self.sender_address}'
        assert self._processing_tx is not None, f'processing tx is None in the sender tx pool {self.sender_address}'

        t_tx = self.get_top_tx()
        p_tx = self._processing_tx
        assert tx.signature == p_tx.signature, f'tx {tx.signature} is not equal to the processing tx {p_tx.signature}'
        assert t_tx is p_tx, f'top tx {t_tx.signature} is not equal to the processing tx {p_tx.signature}'

    def done_tx(self, tx: MPTxRequest) -> None:
        self._validate_processing_tx(tx)

        self._tx_nonce_queue.pop(self._top_index)
        self.debug(f"Pop tx {tx.signature}. The {len(self)} txs are left")
        self._processing_tx = None

    def cancel_process_tx(self, tx: MPTxRequest) -> None:
        self._validate_processing_tx(tx)

        self.debug(f"Reset processing tx {tx.signature} back to pending")
        self._processing_tx.neon_tx_exec_cfg = tx.neon_tx_exec_cfg
        self._processing_tx = None

    def drop_tx(self, tx: MPTxRequest) -> None:
        assert tx is not self._processing_tx, 'tx is equal to the processing tx'
        self._tx_nonce_queue.pop(tx)


@logged_group("neon.MemPool")
class MPTxSchedule:
    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._sender_tx_pool_dict: Dict[str, MPSenderTxPool] = {}
        self._tx_dict = MPTxRequestDict()

        self._paused_sender_set: Set[str] = set([])
        self._sender_tx_pool_queue = SortedQueue[MPSenderTxPool, int, str](
            lt_key_func=lambda a: a.get_gas_price(),
            eq_key_func=lambda a: a.sender_address
        )

    def __len__(self) -> int:
        return len(self._sender_tx_pool_queue)

    def _add_sender_tx_impl(self, sender_tx_pool: MPSenderTxPool, tx: MPTxRequest) -> None:
        self.debug(f'Add tx {tx.signature} to the pool')
        sender_tx_pool.add_tx(tx)
        self._tx_dict.add(tx)

        # the first tx in the sender pool
        if len(sender_tx_pool) == 1:
            self._sender_tx_pool_dict[sender_tx_pool.sender_address] = sender_tx_pool

    def _remove_empty_sender_tx_pool(self, sender_tx_pool: MPSenderTxPool) -> None:
        if not sender_tx_pool.is_empty():
            return
        self._sender_tx_pool_dict.pop(sender_tx_pool.sender_address, None)
        self._paused_sender_set.discard(sender_tx_pool.sender_address)

    def _drop_sender_tx_impl(self, sender_tx_pool: MPSenderTxPool, tx: MPTxRequest) -> None:
        self.debug(f'Drop tx {tx.signature} from the pool')
        if (not sender_tx_pool.is_paused()) and sender_tx_pool.is_top_tx(tx):
            self._sender_tx_pool_queue.pop(sender_tx_pool)
        sender_tx_pool.drop_tx(tx)
        self._tx_dict.pop(tx)
        self._remove_empty_sender_tx_pool(sender_tx_pool)

    def _done_sender_tx_impl(self, sender_tx_pool: MPSenderTxPool, tx: MPTxRequest) -> None:
        self.debug(f'Done tx {tx.signature} in the pool')
        sender_tx_pool.done_tx(tx)
        self._tx_dict.pop(tx)
        self._remove_empty_sender_tx_pool(sender_tx_pool)

    def _get_or_create_sender_tx_pool(self, sender_address: str) -> MPSenderTxPool:
        sender_tx_pool = self._sender_tx_pool_dict.get(sender_address, None)
        if sender_tx_pool is None:
            sender_tx_pool = MPSenderTxPool(sender_address)
        return sender_tx_pool

    def _get_sender_tx_pool(self, sender_address: str) -> MPSenderTxPool:
        sender_tx_pool = self._sender_tx_pool_dict.get(sender_address, None)
        assert sender_tx_pool is not None, f'Failed to get sender tx pool by sender address {sender_address}'
        return cast(MPSenderTxPool, sender_tx_pool)

    def _schedule_sender_tx_pool(self, sender_tx_pool: MPSenderTxPool) -> None:
        assert not sender_tx_pool.is_processing(), f'Sender pool {sender_tx_pool.sender_address} is processed'

        tx = sender_tx_pool.get_top_tx()
        with logging_context(req_id=tx.req_id):
            if not sender_tx_pool.is_paused():
                self.debug(f'Include tx {tx.signature} into the execution queue')
                self._sender_tx_pool_queue.add(sender_tx_pool)
                self._paused_sender_set.discard(sender_tx_pool.sender_address)
            else:
                self.debug(f'Include tx {tx.signature} into the paused set')
                self._paused_sender_set.add(sender_tx_pool.sender_address)

    def _set_sender_tx_cnt(self, sender_tx_pool: MPSenderTxPool, state_tx_cnt: int) -> None:
        assert not sender_tx_pool.is_processing(), f'Sender pool {sender_tx_pool.sender_address} is processed'

        if sender_tx_pool.get_state_tx_cnt() >= state_tx_cnt:
            return

        while not sender_tx_pool.is_empty():
            tx = sender_tx_pool.get_top_tx()
            if tx.nonce >= state_tx_cnt:
                break
            self._drop_sender_tx_impl(sender_tx_pool, tx)

        if not sender_tx_pool.is_empty():
            sender_tx_pool.set_state_tx_cnt(state_tx_cnt)

    def add_tx(self, tx: MPTxRequest) -> MPTxSendResult:
        self.debug(f"Try to add tx {tx.signature} into the mempool")

        old_tx = self._tx_dict.get_tx_by_hash(tx.signature)
        if old_tx is not None:
            self.debug(f'Tx {tx.signature} is already in the pool')
            return MPTxSendResult(code=MPTxSendResultCode.AlreadyKnown, state_tx_cnt=None)

        old_tx = self._tx_dict.get_tx_by_sender_nonce(tx)
        if (old_tx is not None) and (old_tx.gas_price > tx.gas_price):
            self.debug(f'Old tx {old_tx.signature} has higher gas price {old_tx.gas_price}')
            return MPTxSendResult(code=MPTxSendResultCode.Underprice, state_tx_cnt=None)

        if self.get_tx_count() > self._capacity:
            lower_tx = self._tx_dict.get_tx_by_lower_gas_price()
            if (lower_tx is not None) and (lower_tx.gas_price > tx.gas_price):
                self.debug(f'Lower tx {lower_tx.signature} has higher gas price {lower_tx.gas_price}')
                return MPTxSendResult(code=MPTxSendResultCode.Underprice, state_tx_cnt=None)

        sender_tx_pool = self._get_or_create_sender_tx_pool(tx.sender_address)
        self.debug(f"Got pool for sender {tx.sender_address} with {len(sender_tx_pool)} txs")

        # this condition checks the processing tx too
        state_tx_cnt = max(tx.neon_tx_exec_cfg.state_tx_cnt, sender_tx_pool.get_state_tx_cnt())
        if state_tx_cnt > tx.nonce:
            self.debug(f'Sender {tx.sender_address} has higher tx counter {state_tx_cnt}')
            return MPTxSendResult(code=MPTxSendResultCode.NonceTooLow, state_tx_cnt=state_tx_cnt)

        # Everything is ok, let's add transaction to the pool
        if old_tx is not None:
            with logging_context(req_id=old_tx.req_id):
                self.debug(f'Replace the tx {old_tx.signature} with the tx {tx.signature}')
                self._drop_sender_tx_impl(sender_tx_pool, old_tx)
        self._add_sender_tx_impl(sender_tx_pool, tx)

        # don't change the status of the processed sender
        if not sender_tx_pool.is_processing():
            self._set_sender_tx_cnt(sender_tx_pool, state_tx_cnt)
            # the tx is the top in the sender pool
            if sender_tx_pool.is_top_tx(tx):
                self._schedule_sender_tx_pool(sender_tx_pool)

        self._check_oversized_and_reduce(tx)
        return MPTxSendResult(code=MPTxSendResultCode.Success, state_tx_cnt=None)

    def get_tx_count(self):
        return len(self._tx_dict)

    def _check_oversized_and_reduce(self, new_tx: MPTxRequest):
        tx_cnt_to_remove = self.get_tx_count() - self._capacity
        if tx_cnt_to_remove > 0:
            self.debug(f'Try to clear {tx_cnt_to_remove} txs by lower price')

        for i in range(tx_cnt_to_remove):
            tx = self._tx_dict.get_tx_by_lower_gas_price()
            if (tx is None) or (tx.signature == new_tx.signature):
                break

            with logging_context(req_id=tx.req_id):
                self.debug(f'Remove tx {tx.signature} by lower gas price')
                sender_tx_pool = self._get_sender_tx_pool(tx.sender_address)
                assert sender_tx_pool.is_processing(), f'Sender tx pool {sender_tx_pool.sender_address} is processed'
                self._drop_sender_tx_impl(sender_tx_pool, tx)

    def acquire_tx_for_execution(self, min_gas_price: int) -> Optional[MPTxRequest]:
        if len(self._sender_tx_pool_queue) == 0:
            return None
        if self._sender_tx_pool_queue[-1].get_top_tx().gas_price < min_gas_price:
            return None

        sender_tx_pool = self._sender_tx_pool_queue.pop(-1)
        tx = sender_tx_pool.process_tx()
        self._tx_dict.process_tx(tx)
        return tx

    def get_pending_tx_count(self, sender_address: str) -> int:
        sender_tx_pool = self._sender_tx_pool_dict.get(sender_address, None)
        return 0 if sender_tx_pool is None else len(sender_tx_pool)

    def get_pending_tx_nonce(self, sender_address: str) -> Optional[int]:
        sender_tx_pool = self._sender_tx_pool_dict.get(sender_address, None)
        return None if sender_tx_pool is None else sender_tx_pool.get_last_nonce()

    def get_pending_tx_by_hash(self, tx_hash: str) -> Optional[NeonTx]:
        tx = self._tx_dict.get_tx_by_hash(tx_hash)
        if tx is not None:
            return tx.neon_tx
        return None

    def _done_tx(self, tx: MPTxRequest) -> None:
        sender_tx_pool = self._get_sender_tx_pool(tx.sender_address)

        self._done_sender_tx_impl(sender_tx_pool, tx)
        self._set_sender_tx_cnt(sender_tx_pool, tx.neon_tx_exec_cfg.state_tx_cnt)

        # the sender pool was removed from the execution queue and from the paused set,
        #   and now should be included into the execution queue
        #                           or into the paused set
        if not sender_tx_pool.is_empty():
            self._schedule_sender_tx_pool(sender_tx_pool)

    def done_tx(self, tx: MPTxRequest) -> None:
        self._done_tx(tx)

    def fail_tx(self, tx: MPTxRequest) -> None:
        self._done_tx(tx)

    def reschedule_tx(self, tx: MPTxRequest) -> bool:
        sender_tx_pool = self._get_sender_tx_pool(tx.sender_address)

        sender_tx_pool.cancel_process_tx(tx)
        self._tx_dict.cancel_process_tx(tx)

        # the sender pool was removed from the execution queue and from the paused set
        #   and now should be included into the execution queue
        self._schedule_sender_tx_pool(sender_tx_pool)
        return True

    def get_paused_sender_list(self) -> List[str]:
        return [sender for sender in self._paused_sender_set]

    def set_sender_state_tx_cnt_list(self, mp_result: MPSenderTxCntResult) -> None:
        for sender_tx_cnt_data in mp_result.sender_tx_cnt_list:
            sender_tx_pool = self._sender_tx_pool_dict.get(sender_tx_cnt_data.sender, None)
            if (sender_tx_pool is None) or (not sender_tx_pool.is_paused()):
                continue

            self._set_sender_tx_cnt(sender_tx_pool, sender_tx_cnt_data.state_tx_cnt)
            if sender_tx_pool.is_empty():
                continue

            # the sender pool was paused,
            #   and now should be included into the execution queue
            if not sender_tx_pool.is_paused():
                self._schedule_sender_tx_pool(sender_tx_pool)
