import logging
from typing import List, Dict, Set, Optional, Tuple, Iterator, cast

from ..common_neon.data import NeonTxExecCfg
from ..common_neon.utils.eth_proto import NeonTx
from ..common_neon.utils.json_logger import logging_context

from .mempool_api import MPTxRequest, MPTxSendResult, MPTxSendResultCode, MPSenderTxCntData, MPTxRequestList
from .sorted_queue import SortedQueue


LOG = logging.getLogger(__name__)


class MPTxRequestDict:
    def __init__(self) -> None:
        self._tx_hash_dict: Dict[str, MPTxRequest] = {}
        self._tx_sender_nonce_dict: Dict[str, MPTxRequest] = {}
        self._tx_gas_price_queue = SortedQueue[MPTxRequest, int, str](
            lt_key_func=lambda a: -a.gas_price,
            eq_key_func=lambda a: a.sig
        )

    def __len__(self) -> int:
        return len(self._tx_hash_dict)

    @staticmethod
    def _sender_nonce(tx: MPTxRequest) -> str:
        return f'{tx.sender_address}:{tx.nonce}'

    def add(self, tx: MPTxRequest) -> None:
        sender_nonce = self._sender_nonce(tx)
        assert tx.sig not in self._tx_hash_dict, f'Tx {tx.sig} is already in dictionary'
        assert sender_nonce not in self._tx_sender_nonce_dict, f'Tx {sender_nonce} is already in dictionary'

        self._tx_hash_dict[tx.sig] = tx
        self._tx_sender_nonce_dict[sender_nonce] = tx
        self._tx_gas_price_queue.add(tx)
        assert len(self._tx_hash_dict) == len(self._tx_sender_nonce_dict) >= len(self._tx_gas_price_queue)

    def pop(self, tx: MPTxRequest) -> MPTxRequest:
        assert tx.sig in self._tx_hash_dict, f'Tx {tx.sig} is absent in dictionary'

        sender_nonce = self._sender_nonce(tx)
        assert sender_nonce in self._tx_sender_nonce_dict, f'Tx {sender_nonce} is absent in dictionary'

        pos = self._tx_gas_price_queue.find(tx)
        # tx was removed from the gas price queue on processing
        if pos is not None:
            self._tx_gas_price_queue.pop(pos)

        self._tx_sender_nonce_dict.pop(sender_nonce)
        return self._tx_hash_dict.pop(tx.sig, None)

    def get_tx_by_hash(self, tx_hash: str) -> Optional[MPTxRequest]:
        return self._tx_hash_dict.get(tx_hash, None)

    def get_tx_by_sender_nonce(self, tx: MPTxRequest) -> Optional[MPTxRequest]:
        return self._tx_sender_nonce_dict.get(self._sender_nonce(tx), None)

    def acquire_tx(self, tx: MPTxRequest) -> None:
        self._tx_gas_price_queue.pop(tx)

    def cancel_process_tx(self, tx: MPTxRequest) -> None:
        self._tx_gas_price_queue.add(tx)

    def get_tx_with_lower_gas_price(self) -> Optional[MPTxRequest]:
        return self._tx_gas_price_queue[-1] if len(self._tx_gas_price_queue) > 0 else None


class MPSenderTxPool:
    _top_index = -1
    _bottom_index = 0

    def __init__(self, sender_address: Optional[str] = None) -> None:
        self._sender_address = sender_address
        self._state_tx_cnt = 0
        self._processing_tx: Optional[MPTxRequest] = None
        self._tx_nonce_queue = SortedQueue[MPTxRequest, int, str](
            lt_key_func=lambda a: -a.nonce,
            eq_key_func=lambda a: a.sig
        )

    @property
    def sender_address(self) -> str:
        return self._sender_address

    @property
    def len_tx_nonce_queue(self) -> int:
        return len(self._tx_nonce_queue)

    def add_tx(self, tx: MPTxRequest) -> None:
        assert self._state_tx_cnt <= tx.nonce, f'Tx {tx.sig} has nonce {tx.nonce} less than {self._state_tx_cnt}'
        self._tx_nonce_queue.add(tx)

    @property
    def top_tx(self) -> Optional[MPTxRequest]:
        return self._tx_nonce_queue[self._top_index] if not self.is_empty() else None

    def is_top_tx(self, tx: MPTxRequest) -> bool:
        top_tx = self.top_tx
        return top_tx.sig == tx.sig if top_tx is not None else False

    def acquire_tx(self) -> MPTxRequest:
        assert not self.is_processing()
        self._processing_tx = self.top_tx
        return self._processing_tx

    @property
    def pending_nonce(self) -> Optional[int]:
        if self.is_empty() or self.is_paused():
            return None

        pending_nonce = self._state_tx_cnt
        for tx in reversed(self._tx_nonce_queue):
            if tx.nonce != pending_nonce:
                break
            pending_nonce += 1
        return pending_nonce

    @property
    def last_nonce(self) -> Optional[int]:
        return self._tx_nonce_queue[self._bottom_index].nonce if not self.is_empty() else None

    @property
    def gas_price(self) -> int:
        tx = self.top_tx
        return tx.gas_price if tx is not None else 0

    def is_empty(self) -> bool:
        return self.len_tx_nonce_queue == 0

    def is_processing(self) -> bool:
        return self._processing_tx is not None

    @property
    def state_tx_cnt(self) -> int:
        if self.is_processing():
            assert self._state_tx_cnt == self._processing_tx.nonce
            return self._processing_tx.nonce + 1
        return self._state_tx_cnt

    def set_state_tx_cnt(self, value: int) -> None:
        assert not self.is_empty()

        self._state_tx_cnt = value

    def is_paused(self) -> bool:
        assert not self.is_empty()
        return self._state_tx_cnt != self.top_tx.nonce

    def _validate_processing_tx(self, tx: MPTxRequest) -> None:
        assert not self.is_empty(), f'no transactions in {self.sender_address} pool'
        assert self.is_processing(), f'{self.sender_address} pool does not process tx {tx.sig}'

        t_tx = self.top_tx
        p_tx = self._processing_tx
        assert tx.sig == p_tx.sig, f'tx {tx.sig} is not equal to processing tx {p_tx.sig}'
        assert t_tx is p_tx, f'top tx {t_tx.sig} is not equal to processing tx {p_tx.sig}'

    def done_tx(self, tx: MPTxRequest) -> None:
        self._validate_processing_tx(tx)

        self._tx_nonce_queue.pop(self._top_index)
        LOG.debug(f'Done tx {tx.sig}. There are {self.len_tx_nonce_queue} txs left in {self.sender_address} pool')
        self._processing_tx = None

    def cancel_process_tx(self, tx: MPTxRequest, neon_tx_exec_cfg: NeonTxExecCfg) -> None:
        self._validate_processing_tx(tx)

        LOG.debug(f'Reset processing state of tx {tx.sig} back to pending state in {self.sender_address} pool')
        self._processing_tx.neon_tx_exec_cfg = neon_tx_exec_cfg
        self._processing_tx = None

    def take_out_tx_list(self) -> MPTxRequestList:
        is_processing = self.is_processing()
        LOG.debug(
            f'Take out txs from sender pool: {self.sender_address}, count: {self.len_tx_nonce_queue}, '
            f'processing: {is_processing}'
        )
        _from = 1 if is_processing else 0
        taken_out_tx_list = self._tx_nonce_queue.extract_list_from(_from)
        return taken_out_tx_list

    def drop_tx(self, tx: MPTxRequest) -> None:
        if self.is_processing():
            assert tx.sig != self._processing_tx.sig, f'cannot drop processing tx {tx.sig}'
        self._tx_nonce_queue.pop(tx)
        LOG.debug(f'Drop tx {tx.sig}. There are {self.len_tx_nonce_queue} txs left in {self.sender_address} pool')


class MPTxSchedule:
    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._tx_dict = MPTxRequestDict()

        self._sender_pool_dict: Dict[str, MPSenderTxPool] = dict()
        self._paused_sender_set: Set[str] = set()
        self._sender_pool_queue = SortedQueue[MPSenderTxPool, int, str](
            lt_key_func=lambda a: a.gas_price,
            eq_key_func=lambda a: a.sender_address
        )

    def _add_tx_to_sender_pool(self, sender_pool: MPSenderTxPool, tx: MPTxRequest) -> None:
        LOG.debug(f'Add tx {tx.sig} to mempool with {self.tx_cnt} txs')
        sender_pool.add_tx(tx)
        self._tx_dict.add(tx)

        # the first tx in the sender pool
        if sender_pool.len_tx_nonce_queue == 1:
            self._sender_pool_dict[sender_pool.sender_address] = sender_pool

    def _remove_empty_sender_pool(self, sender_pool: MPSenderTxPool) -> None:
        if not sender_pool.is_empty():
            return
        # No reasons to check sender_pool_queue, because sender_pool is empty
        self._sender_pool_dict.pop(sender_pool.sender_address, None)
        self._paused_sender_set.discard(sender_pool.sender_address)

    def _drop_tx_from_sender_pool(self, sender_pool: MPSenderTxPool, tx: MPTxRequest) -> None:
        LOG.debug(f'Drop tx {tx.sig} from pool {sender_pool.sender_address}')
        if (not sender_pool.is_paused()) and sender_pool.is_top_tx(tx):
            LOG.debug(f'Pause sender pool {sender_pool.sender_address}')
            self._sender_pool_queue.pop(sender_pool)
            self._paused_sender_set.add(sender_pool.sender_address)

        sender_pool.drop_tx(tx)
        self._tx_dict.pop(tx)
        self._remove_empty_sender_pool(sender_pool)

    def _done_tx_in_sender_pool(self, sender_pool: MPSenderTxPool, tx: MPTxRequest) -> None:
        LOG.debug(f'Done tx {tx.sig} in pool {sender_pool.sender_address}')
        sender_pool.done_tx(tx)
        self._tx_dict.pop(tx)
        self._remove_empty_sender_pool(sender_pool)

    def _find_sender_pool(self, sender_address: str) -> Optional[MPSenderTxPool]:
        return self._sender_pool_dict.get(sender_address, None)

    def _get_or_create_sender_pool(self, sender_address: str) -> MPSenderTxPool:
        sender_pool = self._find_sender_pool(sender_address)
        if sender_pool is None:
            sender_pool = MPSenderTxPool(sender_address)
        return sender_pool

    def _get_sender_pool(self, sender_address: str) -> MPSenderTxPool:
        sender_pool = self._find_sender_pool(sender_address)
        assert sender_pool is not None, f'Failed to get sender tx pool by sender address {sender_address}'
        return cast(MPSenderTxPool, sender_pool)

    def _schedule_sender_pool(self, sender_pool: MPSenderTxPool) -> None:
        assert not sender_pool.is_processing(), f'Cannot schedule processing pool {sender_pool.sender_address}'

        tx = sender_pool.top_tx
        with logging_context(req_id=tx.req_id):
            if not sender_pool.is_paused():
                LOG.debug(f'Include tx {tx.sig} into execution queue')
                self._sender_pool_queue.add(sender_pool)
                self._paused_sender_set.discard(sender_pool.sender_address)
            else:
                # sender_pool can be already in the paused set
                LOG.debug(f'Include tx {tx.sig} into paused set')
                self._paused_sender_set.add(sender_pool.sender_address)

    def _set_sender_tx_cnt(self, sender_pool: MPSenderTxPool, state_tx_cnt: int) -> None:
        assert not sender_pool.is_processing(), f'Cannot update processing pool {sender_pool.sender_address}'

        if sender_pool.state_tx_cnt == state_tx_cnt:
            return

        while True:
            tx = sender_pool.top_tx
            if tx.nonce >= state_tx_cnt:
                break

            self._drop_tx_from_sender_pool(sender_pool, tx)
            if sender_pool.is_empty():
                return

        sender_pool.set_state_tx_cnt(state_tx_cnt)

    def add_tx(self, tx: MPTxRequest) -> MPTxSendResult:
        LOG.debug(f'Try to add tx {tx.sig} (gas price {tx.gas_price}) to mempool with {self.tx_cnt} txs')

        old_tx = self._tx_dict.get_tx_by_hash(tx.sig)
        if old_tx is not None:
            LOG.debug(f'Tx {tx.sig} is already in mempool')
            return MPTxSendResult(code=MPTxSendResultCode.AlreadyKnown, state_tx_cnt=None)

        old_tx = self._tx_dict.get_tx_by_sender_nonce(tx)
        if (old_tx is not None) and (old_tx.gas_price > tx.gas_price):
            LOG.debug(f'Old tx {old_tx.sig} has higher gas price {old_tx.gas_price} > {tx.gas_price}')
            return MPTxSendResult(code=MPTxSendResultCode.Underprice, state_tx_cnt=None)

        if self.tx_cnt >= self._capacity:
            lower_tx = self._tx_dict.get_tx_with_lower_gas_price()
            if (lower_tx is not None) and (lower_tx.gas_price > tx.gas_price):
                LOG.debug(f'Lowermost tx {lower_tx.sig} has higher gas price {lower_tx.gas_price} > {tx.gas_price}')
                return MPTxSendResult(code=MPTxSendResultCode.Underprice, state_tx_cnt=None)

        sender_pool = self._get_or_create_sender_pool(tx.sender_address)
        LOG.debug(f'Got sender pool {tx.sender_address} with {sender_pool.len_tx_nonce_queue} txs')

        if sender_pool.is_processing():
            top_tx = sender_pool.top_tx
            if top_tx.nonce == tx.nonce:
                LOG.debug(f'Old tx {top_tx.sig} (gas price {top_tx.gas_price}) is processing')
                return MPTxSendResult(code=MPTxSendResultCode.NonceTooLow, state_tx_cnt=top_tx.nonce)

        # this condition checks the processing tx too
        state_tx_cnt = max(tx.neon_tx_exec_cfg.state_tx_cnt, sender_pool.state_tx_cnt)
        if state_tx_cnt > tx.nonce:
            LOG.debug(f'Sender {tx.sender_address} has higher tx counter {state_tx_cnt} > {tx.nonce}')
            return MPTxSendResult(code=MPTxSendResultCode.NonceTooLow, state_tx_cnt=state_tx_cnt)

        # Everything is ok, let's add transaction to the pool
        if old_tx is not None:
            with logging_context(req_id=old_tx.req_id):
                LOG.debug(
                    f'Replace tx {old_tx.sig} (gas price {old_tx.gas_price}) '
                    f'with tx {tx.sig} (gas price {tx.gas_price})'
                )
                self._drop_tx_from_sender_pool(sender_pool, old_tx)
        self._add_tx_to_sender_pool(sender_pool, tx)

        # don't change the status of the processed sender
        if not sender_pool.is_processing():
            self._set_sender_tx_cnt(sender_pool, state_tx_cnt)
            # the tx is the top in the sender pool
            if sender_pool.is_top_tx(tx):
                self._schedule_sender_pool(sender_pool)

        self._check_oversized_and_reduce(tx)
        return MPTxSendResult(code=MPTxSendResultCode.Success, state_tx_cnt=None)

    @property
    def tx_cnt(self) -> int:
        return len(self._tx_dict)

    def _check_oversized_and_reduce(self, new_tx: MPTxRequest) -> None:
        tx_cnt_to_remove = self.tx_cnt - self._capacity
        if tx_cnt_to_remove <= 0:
            return

        LOG.debug(f'Try to clear {tx_cnt_to_remove} txs by lower gas price')
        for i in range(tx_cnt_to_remove):
            tx = self._tx_dict.get_tx_with_lower_gas_price()
            if (tx is None) or (tx.sig == new_tx.sig):
                break

            with logging_context(req_id=tx.req_id):
                LOG.debug(f'Remove tx {tx.sig} from {tx.sender_address} pool by lower gas price {tx.gas_price}')
                sender_pool = self._get_sender_pool(tx.sender_address)
                self._drop_tx_from_sender_pool(sender_pool, tx)

    def peek_tx(self) -> Optional[MPTxRequest]:
        if len(self._sender_pool_queue) == 0:
            return None
        return self._sender_pool_queue[-1].top_tx

    def acquire_tx(self) -> Optional[MPTxRequest]:
        sender_pool = self._sender_pool_queue.pop(-1)
        tx = sender_pool.acquire_tx()
        self._tx_dict.acquire_tx(tx)
        return tx

    def get_pending_tx_count(self, sender_address: str) -> int:
        sender_pool = self._find_sender_pool(sender_address)
        return 0 if sender_pool is None else sender_pool.len_tx_nonce_queue

    def get_pending_tx_nonce(self, sender_address: str) -> Optional[int]:
        sender_pool = self._find_sender_pool(sender_address)
        return None if sender_pool is None else sender_pool.pending_nonce

    def get_last_tx_nonce(self, sender_address: str) -> Optional[int]:
        sender_pool = self._find_sender_pool(sender_address)
        return None if sender_pool is None else sender_pool.last_nonce

    def get_pending_tx_by_hash(self, tx_hash: str) -> Optional[NeonTx]:
        tx = self._tx_dict.get_tx_by_hash(tx_hash)
        return None if tx is None else tx.neon_tx

    def _done_tx(self, tx: MPTxRequest) -> None:
        sender_pool = self._get_sender_pool(tx.sender_address)

        self._done_tx_in_sender_pool(sender_pool, tx)
        if sender_pool.is_empty():
            return

        self._set_sender_tx_cnt(sender_pool, tx.neon_tx_exec_cfg.state_tx_cnt)

        # the sender pool was removed from the execution queue and from the paused set,
        #   and now should be included into the execution queue
        #                           or into the paused set
        self._schedule_sender_pool(sender_pool)

    def done_tx(self, tx: MPTxRequest) -> None:
        self._done_tx(tx)

    def fail_tx(self, tx: MPTxRequest) -> None:
        self._done_tx(tx)

    def cancel_tx(self, tx: MPTxRequest) -> bool:
        sender_pool = self._get_sender_pool(tx.sender_address)

        sender_pool.cancel_process_tx(tx, tx.neon_tx_exec_cfg)
        self._tx_dict.cancel_process_tx(tx)

        self._set_sender_tx_cnt(sender_pool, tx.neon_tx_exec_cfg.state_tx_cnt)

        # the sender pool was removed from the execution queue and from the paused set
        #   and now should be included into the execution queue
        self._schedule_sender_pool(sender_pool)
        return True

    @property
    def paused_sender_list(self) -> List[str]:
        return list(self._paused_sender_set)

    def set_sender_state_tx_cnt_list(self, sender_tx_cnt_list: List[MPSenderTxCntData]) -> None:
        for sender_tx_cnt_data in sender_tx_cnt_list:
            sender_pool = self._find_sender_pool(sender_tx_cnt_data.sender)
            if (sender_pool is None) or (not sender_pool.is_paused()):
                continue

            self._set_sender_tx_cnt(sender_pool, sender_tx_cnt_data.state_tx_cnt)
            if sender_pool.is_empty():
                continue

            # the sender pool was paused,
            #   and now should be included into the execution queue
            elif not sender_pool.is_paused():
                self._schedule_sender_pool(sender_pool)

    @property
    def taking_out_tx_list_iter(self) -> Iterator[Tuple[str, MPTxRequestList]]:
        empty_pool_list: List[MPSenderTxPool] = list()

        for sender_address, tx_pool in self._sender_pool_dict.items():
            taken_out_tx_list = tx_pool.take_out_tx_list()
            for tx in taken_out_tx_list:
                self._tx_dict.pop(tx)
            if tx_pool.is_empty():
                empty_pool_list.append(tx_pool)
            yield sender_address, taken_out_tx_list

        for tx_pool in empty_pool_list:
            self._remove_empty_sender_pool(tx_pool)
        self._sender_pool_queue.remove_if(lambda sender_pool: sender_pool.is_empty())

    def take_in_tx_list(self, sender_address: str, mp_tx_request_list: MPTxRequestList):
        LOG.debug(f'Take in mp_tx_request_list, sender_addr: {sender_address}, {len(mp_tx_request_list)} - txs')
        for mp_tx_request in mp_tx_request_list:
            self.add_tx(mp_tx_request)
