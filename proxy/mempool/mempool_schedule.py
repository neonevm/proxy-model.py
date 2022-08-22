import bisect
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

from logged_groups import logged_group

from ..common_neon.eth_proto import Trx as NeonTx

from .mempool_api import MPTxRequest, MPSendTxResult


@logged_group("neon.MemPool")
class MPTxDict:
    def __init__(self) -> None:
        self._tx_hash_dict: Dict[str, MPTxRequest] = {}

    def add(self, tx: MPTxRequest) -> bool:
        if tx.signature in self._tx_hash_dict:
            self.error(f'Tx {tx.signature} is already in the dictionary', extra=tx.log_req_id)
            return False

        self._tx_hash_dict[tx.signature] = tx
        return True

    def pop(self, tx: MPTxRequest) -> bool:
        popped_tx = self._tx_hash_dict.pop(tx.signature, None)
        if popped_tx is None:
            self.error(f'Tx {tx.signature} does not exist in the dictionary', extra=tx.log_req_id)
        return popped_tx is not None

    def get(self, tx_hash: str) -> Optional[MPTxRequest]:
        return self._tx_hash_dict.get(tx_hash, None)


@logged_group("neon.MemPool")
class MPSenderTxPool:
    def __init__(self, sender_address: Optional[str] = None, tx_dict: Optional[MPTxDict] = None):
        self.sender_address = sender_address
        self._tx_dict = tx_dict
        self._tx_list: List[MPTxRequest] = []
        self._processing_tx: Optional[MPTxRequest] = None

    def __eq__(self, other):
        return self.first_tx_gas_price() == other.first_tx_gas_price()

    def __lt__(self, other):
        return self.first_tx_gas_price() > other.first_tx_gas_price()

    def _on_add_tx(self, tx: MPTxRequest):
        if self._tx_dict is None:
            return
        self._tx_dict.add(tx)

    def _on_pop_tx(self, tx: MPTxRequest):
        if self._tx_dict is None:
            return
        self._tx_dict.pop(tx)

    def add_tx(self, mp_tx_request: MPTxRequest) -> MPSendTxResult:
        index = bisect.bisect_left(self._tx_list, mp_tx_request)
        last_nonce = self.last_nonce()
        if self._processing_tx is not None and mp_tx_request.nonce == self._processing_tx.nonce:
            tx = self._processing_tx
            self.warning(
                f"Failed to replace processing tx {tx.signature} with {mp_tx_request.signature}",
                extra=mp_tx_request.log_req_id
            )
            return MPSendTxResult(success=False, last_nonce=last_nonce)

        found_tx: Optional[MPTxRequest] = self._tx_list[index] if index < len(self._tx_list) else None
        if found_tx is not None and found_tx.nonce == mp_tx_request.nonce:
            self.debug(
                f"Nonce are equal: {found_tx.nonce}, found tx {found_tx.signature}, new tx {mp_tx_request.signature}",
                extra=mp_tx_request.log_req_id
            )
            if found_tx.gas_price < mp_tx_request.gas_price:
                self._on_pop_tx(found_tx)
                self._tx_list[index] = mp_tx_request
                self._on_add_tx(mp_tx_request)
                return MPSendTxResult(success=True, last_nonce=last_nonce)
            return MPSendTxResult(success=False, last_nonce=last_nonce)

        if (last_nonce is not None) and (mp_tx_request.nonce != last_nonce + 1):
            return MPSendTxResult(success=False, last_nonce=last_nonce)

        if (last_nonce is None) and (mp_tx_request.nonce != mp_tx_request.sender_tx_cnt):
            return MPSendTxResult(success=False, last_nonce=last_nonce)

        self._tx_list.insert(index, mp_tx_request)
        self._on_add_tx(mp_tx_request)
        self.debug(f"New tx {mp_tx_request.signature} - inserted at: {index}", mp_tx_request.log_req_id)
        return MPSendTxResult(success=True, last_nonce=last_nonce)

    def get_tx(self):
        return None if self.is_empty() else self._tx_list[0]

    def acquire_tx(self):
        if self.is_processing():
            return None
        self._processing_tx = self.get_tx()
        return self._processing_tx

    def len(self) -> int:
        return len(self._tx_list)

    def last_nonce(self) -> Optional[int]:
        if self.len() == 0:
            return None
        return self._tx_list[-1].nonce

    def first_tx_gas_price(self):
        tx = self.get_tx()
        return tx.gas_price if tx is not None else 0

    def _validate_processing_tx(self, action: str, mp_tx_request: MPTxRequest) -> bool:
        if self._processing_tx is None:
            self.error(f"Failed to {action} tx, processing tx is None", extra=mp_tx_request.log_req_id)
            return False
        if self._processing_tx.nonce != mp_tx_request.nonce:
            self.error(
                f"Failed to {action} tx, "
                f"processing tx has different nonce: {self._processing_tx.nonce} than: {mp_tx_request.nonce}",
                extra=mp_tx_request.log_req_id
            )
            return False

        if self.is_empty():
            self.error(f"Failed to {action} tx, sender doesn't have transactions", extra=mp_tx_request.log_req_id)
            return False
        tx = self._tx_list[0]
        if tx is not self._processing_tx:
            self.error(
                f"Failed to {action} tx, " +
                f"processing tx has another signature: {self._processing_tx.signature} than: {tx.signature}",
                extra=mp_tx_request.log_req_id
            )
            return False

        if mp_tx_request.signature != self._processing_tx.signature:
            self.error(
                f"Failed to {action} tx, " +
                f"tx has another signature: {self._processing_tx.signature} than: {mp_tx_request.signature}",
                extra=mp_tx_request.log_req_id
            )
            return False

        return True

    def done_tx(self, mp_tx_request: MPTxRequest):
        if not self._validate_processing_tx('finish', mp_tx_request):
            return

        self._tx_list = self._tx_list[1:]
        self._on_pop_tx(self._processing_tx)
        self.debug(f"On tx done - removed. The: {self.len()} txs are left", extra=mp_tx_request.log_req_id)
        self._processing_tx = None

    def is_empty(self) -> bool:
        return self.len() == 0

    def is_processing(self) -> bool:
        return self._processing_tx is not None

    def drop_last_request(self) -> bool:
        if self.is_empty():
            self.error("Failed to drop last request from empty sender tx pool")
            return False
        tx = self._tx_list[-1]
        if self._processing_tx is tx:
            self.debug(f"Skip removing transaction {tx.signature} - processing", extra=tx.log_req_id)
            return False

        self.debug(f"Remove last mp_tx_request.", extra=tx.log_req_id)
        self._tx_list.pop()
        self._on_pop_tx(tx)
        return True

    def fail_tx(self, mp_tx_request: MPTxRequest):
        self.debug(f"Remove mp_tx_request", extra=mp_tx_request.log_req_id)
        if not self._validate_processing_tx('drop', mp_tx_request):
            return

        for tx in self._tx_list:
            self.debug(f"Removed mp_tx_request from sender.", extra=mp_tx_request.log_req_id)
            self._on_pop_tx(tx)

        self._tx_list.clear()
        self._processing_tx = None

    def reschedule_tx(self, mp_tx_request: MPTxRequest):
        self.debug(f"Reschedule mp_tx_request.", extra=mp_tx_request.log_req_id)
        if not self._validate_processing_tx('reschedule', mp_tx_request):
            return

        self.debug(f"Reset processing tx back to pending", extra=mp_tx_request.log_req_id)
        self._processing_tx = None


@dataclass
class MPSenderTxPosition:
    sender_tx_pool: MPSenderTxPool
    position: int


@logged_group("neon.MemPool")
class MPTxSchedule:
    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._sender_tx_pool_list: List[MPSenderTxPool] = []
        self._sender_tx_pool_dict: Dict[str, MPSenderTxPool] = {}
        self._tx_dict = MPTxDict()

    def len(self) -> int:
        return len(self._sender_tx_pool_dict)

    def _pop_sender_tx_pool(self, sender_address: str) -> Optional[MPSenderTxPool]:
        for i, sender_tx_pool in enumerate(self._sender_tx_pool_list):
            if sender_tx_pool.sender_address != sender_address:
                continue
            return self._sender_tx_pool_list.pop(i)
        return None

    def _pop_or_create_tx_sender_pool(self, sender_address: str) -> MPSenderTxPool:
        sender_tx_pool = self._pop_sender_tx_pool(sender_address)
        if sender_tx_pool is None:
            sender_tx_pool = MPSenderTxPool(sender_address, self._tx_dict)
        return sender_tx_pool

    def _get_sender_tx_pool(self, sender_address: str) -> Tuple[Optional[MPSenderTxPool], int]:
        for i, sender in enumerate(self._sender_tx_pool_list):
            if sender.sender_address != sender_address:
                continue
            return sender, i
        return None, -1

    def add_mp_tx_request(self, mp_tx_request: MPTxRequest) -> MPSendTxResult:
        self.debug(f"Add mp_tx_request", extra=mp_tx_request.log_req_id)
        sender_txs = self._pop_or_create_tx_sender_pool(mp_tx_request.sender_address)
        self.debug(
            f"Got collection for sender: {mp_tx_request.sender_address}, there are already txs: {sender_txs.len()}",
            extra=mp_tx_request.log_req_id
        )
        result: MPSendTxResult = sender_txs.add_tx(mp_tx_request)
        bisect.insort_left(self._sender_tx_pool_list, sender_txs)

        self._check_oversized_and_reduce()
        return result

    def get_mp_tx_count(self):
        count = 0
        for sender_txs in self._sender_tx_pool_list:
            count += sender_txs.len()
        return count

    def _check_oversized_and_reduce(self):
        count = self.get_mp_tx_count()
        tx_to_remove = count - self._capacity
        sender_to_remove = []
        for sender in self._sender_tx_pool_list[::-1]:
            if tx_to_remove <= 0:
                break
            if not sender.drop_last_request():
                continue
            if sender.is_empty():
                sender_to_remove.append(sender)
            tx_to_remove -= 1
        for sender in sender_to_remove:
            self._sender_tx_pool_list.remove(sender)

    def acquire_tx_for_execution(self) -> Optional[MPTxRequest]:
        if len(self._sender_tx_pool_list) == 0:
            return None

        tx: Optional[MPTxRequest] = None
        for sender_txs in self._sender_tx_pool_list:
            tx = sender_txs.acquire_tx()
            if tx is None:
                continue
            break

        return tx

    def get_pending_tx_count(self, sender_addr: str) -> int:
        sender, _ = self._get_sender_tx_pool(sender_addr)
        return 0 if sender is None else sender.len()

    def get_pending_tx_nonce(self, sender_addr: str) -> int:
        sender, _ = self._get_sender_tx_pool(sender_addr)
        return None if sender is None else sender.last_nonce()

    def get_pending_tx_by_hash(self, tx_hash: str) -> Optional[NeonTx]:
        tx = self._tx_dict.get(tx_hash)
        if tx is not None:
            return tx.neon_tx
        return None

    def done_tx(self, mp_tx_request: MPTxRequest) -> bool:
        sender = self._pop_sender_tx_pool(mp_tx_request.sender_address)
        if sender is None:
            self.error(
                f"Failed to process tx done, no sender by sender_address: {mp_tx_request.sender_address}",
                extra=mp_tx_request.log_req_id
            )
            return False
        sender.done_tx(mp_tx_request)
        if not sender.is_empty():
            bisect.insort_left(self._sender_tx_pool_list, sender)
        return True

    def fail_tx(self, mp_tx_request: MPTxRequest) -> bool:
        sender, i = self._get_sender_tx_pool(mp_tx_request.sender_address)
        if sender is None:
            self.error(
                f"Failed to drop request, no sender by sender_address: {mp_tx_request.sender_address}",
                extra=mp_tx_request.log_req_id
            )
            return False
        sender.fail_tx(mp_tx_request)
        if sender.len() == 0:
            self._sender_tx_pool_list.pop(i)
        return True

    def reschedule_tx(self, mp_tx_request: MPTxRequest):
        sender, _ = self._get_sender_tx_pool(mp_tx_request.sender_address)
        if sender is None:
            self.error(
                f"Failed to reschedule request, no sender by sender_address: {mp_tx_request.sender_address}",
                extra=mp_tx_request.log_req_id
            )
            return
        sender.reschedule_tx(mp_tx_request)
