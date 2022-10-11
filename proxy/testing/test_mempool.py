from __future__ import annotations

import asyncio
import logging
from random import randint

from web3 import Web3, Account
from eth_account.account import LocalAccount
from typing import Any, List, Dict, Optional, Union

import unittest
from unittest.mock import patch, MagicMock, call

from ..common_neon.config import Config
from ..common_neon.data import NeonTxExecCfg
from ..common_neon.solana_transaction import SolPubKey

from ..mempool.mempool import MemPool, IMPExecutor, MPTask, MPTxRequestList
from ..mempool.mempool_api import MPRequest, MPRequestType
from ..mempool.mempool_api import MPTxExecRequest, MPTxExecResult, MPTxExecResultCode
from ..mempool.mempool_api import MPGasPriceResult, MPSenderTxCntData
from ..mempool.mempool_schedule import MPTxSchedule, MPSenderTxPool
from ..common_neon.eth_proto import NeonTx
from ..common_neon.elf_params import ElfParams

from .testing_helpers import create_account
from ..mempool.operator_resource_mng import OpResMng


def get_transfer_mp_request(*, req_id: str, nonce: int, gas: int, gas_price: int,
                            from_acc: Union[Account, LocalAccount, None] = None,
                            to_acc: Union[Account, LocalAccount, None] = None,
                            value: int = 0, data: bytes = b'') -> MPTxExecRequest:
    if from_acc is None:
        from_acc = create_account()

    if to_acc is None:
        to_acc = create_account()
    to_addr = to_acc.address
    w3 = Web3()
    signed_tx_data = w3.eth.account.sign_transaction(
        dict(nonce=nonce, chainId=111, gas=gas, gasPrice=gas_price, to=to_addr, value=value, data=data),
        from_acc.key)
    neon_sig = signed_tx_data.hash.hex()
    neon_tx = NeonTx.fromString(bytearray(signed_tx_data.rawTransaction))
    neon_tx_exec_cfg = NeonTxExecCfg()
    neon_tx_exec_cfg.set_state_tx_cnt(0)
    mp_tx_request = MPTxExecRequest(
        req_id=req_id,
        sig=neon_sig,
        neon_tx=neon_tx,
        neon_tx_exec_cfg=neon_tx_exec_cfg,
        resource_ident='test',
        elf_param_dict=ElfParams().elf_param_dict
    )
    return mp_tx_request


class MockTask:
    def __init__(self, result: Any, is_done: bool = True, exception: Exception = None):
        self._result = result
        self._is_done = is_done
        self._exception = exception

    def done(self):
        return self._is_done

    def result(self):
        return self._result

    def exception(self):
        return self._exception


class MockMPExecutor(IMPExecutor):
    def submit_mp_request(self, mp_request: MPRequest) -> MPTask:
        return MPTask(1, MockTask(MPTxExecResult(MPTxExecResultCode.Done, None)), mp_request)

    def is_available(self) -> bool:
        return False

    def release_executor(self, executor_id: int):
        pass


class MockResourceManager(OpResMng):
    def __init__(self, _):
        pass

    def get_resource(self, ident: str) -> Optional[str]:
        return 'test'

    def release_resource(self, ident: str) -> None:
        pass

    def get_disabled_resource_list(self) -> List[str]:
        return []


class FakeConfig(Config):
    @property
    def evm_loader_id(self) -> SolPubKey:
        return SolPubKey('CmA9Z6FjioHJPpjT39QazZyhDRUdZy2ezwx4GiDdE2u2')

    @property
    def mempool_capacity(self) -> int:
        return 4000

    @property
    def recheck_used_resource_sec(self) -> int:
        return 1000

    @property
    def recheck_resource_after_uses_cnt(self) -> int:
        return 1000


class TestMemPool(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.turn_logger_off()

    @classmethod
    def turn_logger_off(cls) -> None:
        neon_logger = logging.getLogger("neon.MemPool")
        neon_logger.setLevel(logging.ERROR)

    async def asyncSetUp(self):
        self._executor = MockMPExecutor()
        self._config = FakeConfig()
        self._op_res_mng = MockResourceManager(self._config)
        self._mempool = MemPool(self._config, self._op_res_mng, self._executor)

        price_result = MPGasPriceResult(suggested_gas_price=1, min_gas_price=1)
        self._mempool._gas_price_task_loop._task = MockTask(None, False)
        self._mempool._gas_price_task_loop._gas_price = price_result

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available", return_value=True)
    async def test_single_sender_single_tx(self, _: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if an enqueued mp_tx_request gets in effect"""
        mp_tx_request = get_transfer_mp_request(
            req_id="0000001", nonce=0, gas_price=30000, gas=987654321, value=1, data=b''
        )
        await self._mempool.enqueue_mp_request(mp_tx_request)
        await asyncio.sleep(0)

        submit_mp_request_mock.assert_called_once()
        submit_mp_request_mock.assert_called_with(mp_tx_request)

    @patch.object(MockMPExecutor, "submit_mp_request",
                  return_value=(1, MockTask(MPTxExecResult(MPTxExecResultCode.Done, None))))
    @patch.object(MockMPExecutor, "is_available", return_value=False)
    async def test_single_sender_couple_txs(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if an enqueued mp_tx_requests get in effect in the right order"""
        from_acc = create_account()
        to_acc = create_account()
        req_data = [
            dict(req_id="0000000", nonce=0, gas_price=30000, gas=987654321, value=1, from_acc=from_acc, to_acc=to_acc),
            dict(req_id="0000001", nonce=1, gas_price=29000, gas=987654321, value=1, from_acc=from_acc, to_acc=to_acc)
        ]
        requests = await self._enqueue_requests(req_data)
        await asyncio.sleep(0)
        submit_mp_request_mock.assert_not_called()
        is_available_mock.return_value = True
        self._mempool.on_executor_got_available(1)
        await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC * 2)
        submit_mp_request_mock.assert_has_calls([call(requests[0])])

        self._update_state_tx_cnt([MPSenderTxCntData(sender=from_acc.address.lower(), state_tx_cnt=1)])
        self._mempool.on_executor_got_available(1)
        await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC * 2)
        submit_mp_request_mock.assert_has_calls([call(requests[0]), call(requests[1])])

    @patch.object(MockMPExecutor, "submit_mp_request",
                  return_value=(1, MockTask(MPTxExecResult(MPTxExecResultCode.Done, None))))
    @patch.object(MockMPExecutor, "is_available", return_value=False)
    async def test_2_senders_4_txs(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if an enqueued mp_tx_request from different senders gets in effect in the right order"""
        acc = [create_account() for _ in range(3)]
        req_data = [dict(req_id="000", nonce=0, gas_price=30000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[2]),
                    dict(req_id="001", nonce=1, gas_price=21000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[2]),
                    dict(req_id="002", nonce=0, gas_price=40000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2]),
                    dict(req_id="003", nonce=1, gas_price=25000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2])]
        requests = await self._enqueue_requests(req_data)
        is_available_mock.return_value = True
        self._mempool.on_executor_got_available(1)
        await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC * 2)
        submit_mp_request_mock.assert_has_calls([call(requests[2]), call(requests[0])])

        self._update_state_tx_cnt([
            MPSenderTxCntData(sender=acc[0].address.lower(), state_tx_cnt=1),
            MPSenderTxCntData(sender=acc[1].address.lower(), state_tx_cnt=1)])
        self._mempool.on_executor_got_available(1)
        await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC * 2)
        submit_mp_request_mock.assert_has_calls(
            [call(requests[2]), call(requests[0]), call(requests[3]), call(requests[1])]
        )

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    async def test_mp_waits_for_previous_tx_done(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if an enqueued mp_tx_request waits for the previous one from the same sender"""
        submit_mp_request_mock.return_value = (1, MockTask(None, is_done=False))
        is_available_mock.return_value = False
        acc_0 = create_account()
        acc_1 = create_account()
        req_data = [dict(req_id="000", nonce=0, gas_price=10000, gas=1000, value=1, from_acc=acc_0, to_acc=acc_1),
                    dict(req_id="001", nonce=1, gas_price=10000, gas=1500, value=2, from_acc=acc_0, to_acc=acc_1)]
        requests = await self._enqueue_requests(req_data)
        is_available_mock.return_value = True
        for i in range(2):
            await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC)
            self._mempool.on_executor_got_available(1)
        submit_mp_request_mock.assert_called_once_with(requests[0])

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    async def test_subst_with_higher_gas_price(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if the transaction with the same nonce but the higher gas_price substitutes the current one"""
        from_acc = create_account()
        base_request = get_transfer_mp_request(
            req_id="0", from_acc=from_acc, nonce=0, gas_price=30000, gas=987654321, value=1, data=b''
        )
        await self._mempool.schedule_mp_tx_request(base_request)
        subst_request = get_transfer_mp_request(
            req_id="1", from_acc=from_acc, nonce=0, gas_price=40000, gas=987654321, value=2, data=b''
        )
        await self._mempool.schedule_mp_tx_request(subst_request)
        is_available_mock.return_value = True
        self._mempool.on_executor_got_available(1)
        await asyncio.sleep(0)
        submit_mp_request_mock.assert_called_once()
        submit_mp_request_mock.assert_called_with(subst_request)

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    async def test_subst_with_lower_gas_price(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if the transaction with the same nonce but the lower gas_price is ignored"""
        from_acc = create_account()
        base_request = get_transfer_mp_request(
            req_id="0", from_acc=from_acc, nonce=0, gas_price=40000, gas=987654321, value=1, data=b''
        )
        await self._mempool.schedule_mp_tx_request(base_request)
        subst_request = get_transfer_mp_request(
            req_id="1", from_acc=from_acc, nonce=0, gas_price=30000, gas=987654321, value=2, data=b''
        )
        await self._mempool.schedule_mp_tx_request(subst_request)
        is_available_mock.return_value = True
        self._mempool.on_executor_got_available(1)
        await asyncio.sleep(0)
        submit_mp_request_mock.assert_called_once()
        submit_mp_request_mock.assert_called_with(base_request)

    @patch.object(MockMPExecutor, "is_available")
    async def test_check_pending_tx_count(self, is_available_mock: MagicMock):
        """Checks if all incoming mp_tx_requests those are not processed are counted as pending"""
        acc = [create_account() for _ in range(3)]
        req_data = [dict(req_id="000", nonce=0, gas_price=30000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[2]),
                    dict(req_id="001", nonce=1, gas_price=21000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[2]),
                    dict(req_id="002", nonce=2, gas_price=25000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2]),
                    dict(req_id="003", nonce=0, gas_price=40000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2]),
                    dict(req_id="004", nonce=1, gas_price=25000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2])]
        requests = await self._enqueue_requests(req_data)
        acc_0_count = self._mempool.get_pending_tx_count(requests[0].sender_address)
        self.assertEqual(acc_0_count, 2)
        acc_1_count = self._mempool.get_pending_tx_count(requests[3].sender_address)
        self.assertEqual(acc_1_count, 3)
        is_available_mock.return_value = True
        self._mempool.on_executor_got_available(1)
        await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC)
        acc_1_count = self._mempool.get_pending_tx_count(requests[3].sender_address)
        self.assertEqual(acc_1_count, 2)

    @patch.object(MockMPExecutor, "submit_mp_request",
                  return_value=(1, MockTask(MPTxExecResult(MPTxExecResultCode.Done, None))))
    @patch.object(MockMPExecutor, "is_available")
    async def test_over_9000_transfers(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if all mp_tx_requests are processed by the MemPool"""
        acc_count_max = 1_000
        from_acc_count = 10
        sleep_sec = 0.1
        nonce_count = 100
        acc = [create_account() for _ in range(acc_count_max)]
        for acc_i in range(0, from_acc_count):
            nonces = [i for i in range(0, nonce_count)]
            while len(nonces) > 0:
                index = randint(0, len(nonces) - 1)
                nonce = nonces.pop(index)
                request = get_transfer_mp_request(from_acc=acc[acc_i], to_acc=acc[randint(0, acc_count_max-1)],
                                                  req_id=str(acc_i) + " " + str(nonce), nonce=nonce,
                                                  gas_price=randint(50000, 100000), gas=randint(4000, 10000))
                await self._mempool.enqueue_mp_request(request)
        is_available_mock.return_value = True
        for i in range(nonce_count):
            call_count = 0
            self._mempool.on_executor_got_available(1)
            await asyncio.sleep(sleep_sec)
            for ac in acc[:from_acc_count]:
                acc_nonce = 0
                for mp_call in submit_mp_request_mock.call_args_list:
                    request = mp_call.args[0]
                    if request.type != MPRequestType.SendTransaction:
                        continue
                    if ac.address.lower() == request.sender_address:
                        self.assertEqual(request.nonce, acc_nonce)
                        acc_nonce += 1
                        call_count += 1
            nonce = i + 1
            self.assertEqual(call_count, from_acc_count * nonce)

            update_tx_cnt_list: List[MPSenderTxCntData] = []
            for acc_i in range(0, from_acc_count):
                update_tx_cnt_list.append(MPSenderTxCntData(sender=acc[acc_i].address.lower(), state_tx_cnt=nonce))
            self._update_state_tx_cnt(update_tx_cnt_list)

    async def _enqueue_requests(self, req_data: List[Dict[str, Any]]) -> MPTxRequestList:
        requests = [get_transfer_mp_request(**req) for req in req_data]
        for req in requests:
            await self._mempool.enqueue_mp_request(req)
        return requests

    def _update_state_tx_cnt(self, sender_tx_cnt_list: List[MPSenderTxCntData]) -> None:
        for data in sender_tx_cnt_list:
            tx = self._mempool._tx_schedule._find_sender_pool(data.sender).get_top_tx()
            self._mempool._tx_schedule.done_tx(tx)
        self._mempool._tx_schedule.set_sender_state_tx_cnt_list(sender_tx_cnt_list)


class TestMPSchedule(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.turn_logger_off()

    @classmethod
    def turn_logger_off(cls) -> None:
        neon_logger = logging.getLogger("neon.MemPool")
        neon_logger.setLevel(logging.ERROR)

    def test_capacity_oversized_simple(self):
        """Checks if mp_schedule gets oversized in simple way"""
        mp_schedule_capacity = 5
        schedule = MPTxSchedule(mp_schedule_capacity)
        acc = [create_account() for _ in range(3)]
        req_data = [dict(req_id="000", nonce=1, gas_price=60000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1]),
                    dict(req_id="001", nonce=0, gas_price=60000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1]),
                    dict(req_id="002", nonce=1, gas_price=40000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2]),
                    dict(req_id="003", nonce=1, gas_price=70000, gas=1000, value=1, from_acc=acc[2], to_acc=acc[1]),
                    dict(req_id="004", nonce=0, gas_price=25000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2]),
                    dict(req_id="005", nonce=2, gas_price=50000, gas=1000, value=1, from_acc=acc[2], to_acc=acc[1]),
                    dict(req_id="006", nonce=0, gas_price=50000, gas=1000, value=1, from_acc=acc[2], to_acc=acc[1])]
        self.requests = [get_transfer_mp_request(**req) for req in req_data]
        for request in self.requests[0:5]:
            schedule.add_tx(request)

        self.assertIs(schedule.acquire_tx(), self.requests[1])
        self.assertIs(schedule.acquire_tx(), self.requests[4])
        self.assertIs(schedule.peek_tx(), None)
        for request in self.requests[5:]:
            schedule.add_tx(request)
        self.assertEqual(acc[2].address.lower(), schedule._sender_pool_queue[0].sender_address)
        self.assertIs(self.requests[3], schedule._sender_pool_queue[0]._tx_nonce_queue[0])
        self.assertEqual(5, schedule.get_tx_count())
        self.assertEqual(1, len(schedule._sender_pool_queue))
        self.assertEqual(2, schedule.get_pending_tx_count(acc[0].address.lower()))
        self.assertEqual(1, schedule.get_pending_tx_count(acc[1].address.lower()))
        self.assertEqual(2, schedule.get_pending_tx_count(acc[2].address.lower()))

    def test_capacity_oversized(self):
        """Checks if mp_schedule doesn't get oversized with a quite big set of mp_tx_requests"""
        acc_count_max = 10
        from_acc_count = 5
        nonce_count = 1000
        mp_schedule_capacity = 4000
        schedule = MPTxSchedule(mp_schedule_capacity)
        acc = [create_account() for _ in range(acc_count_max)]
        for acc_i in range(0, from_acc_count):
            nonces = [i for i in range(0, nonce_count)]
            while len(nonces) > 0:
                index = randint(0, len(nonces) - 1)
                nonce = nonces.pop(index)
                request = get_transfer_mp_request(from_acc=acc[acc_i], to_acc=acc[randint(0, acc_count_max-1)],
                                                  req_id=str(acc_i) + " " + str(nonce), nonce=nonce_count - nonce - 1,
                                                  gas_price=randint(50000, 100000), gas=randint(4000, 10000))
                schedule.add_tx(request)
        self.assertEqual(mp_schedule_capacity, schedule.get_tx_count())

    def test_take_out_txs(self):
        mp_schedule_capacity = 4000
        schedule = MPTxSchedule(mp_schedule_capacity)
        acc = [create_account() for _ in range(3)]
        req_data = [dict(req_id="000", nonce=0, gas_price=60000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1]),
                    dict(req_id="001", nonce=1, gas_price=60000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1]),
                    dict(req_id="002", nonce=0, gas_price=40000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2]),
                    dict(req_id="003", nonce=0, gas_price=70000, gas=1000, value=1, from_acc=acc[2], to_acc=acc[1]),
                    dict(req_id="004", nonce=1, gas_price=25000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2]),
                    dict(req_id="005", nonce=1, gas_price=50000, gas=1000, value=1, from_acc=acc[2], to_acc=acc[1]),
                    dict(req_id="006", nonce=2, gas_price=50000, gas=1000, value=1, from_acc=acc[2], to_acc=acc[1])]
        self.requests = [get_transfer_mp_request(**req) for req in req_data]
        for request in self.requests:
            schedule.add_tx(request)
        self.assertEqual(len(schedule._sender_pool_dict), 3)
        self.assertEqual(len(schedule._sender_pool_queue), 3)
        acc0, acc1, acc2 = acc[0].address.lower(), acc[1].address.lower(), acc[2].address.lower()
        awaiting = {acc0: 2, acc1: 2, acc2: 3}

        for sender_addr, txs in schedule.get_taking_out_tx_list_iter():
            self.assertEqual(awaiting[sender_addr], len(txs))

        self.assertEqual(schedule.get_pending_tx_count(acc0), 0)
        self.assertEqual(schedule.get_pending_tx_count(acc1), 0)
        self.assertEqual(schedule.get_pending_tx_count(acc2), 0)


class TestMPSenderTxPool(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.turn_logger_off()

    @classmethod
    def turn_logger_off(cls) -> None:
        neon_logger = logging.getLogger("neon.MemPool")
        neon_logger.setLevel(logging.ERROR)

    def setUp(self) -> None:
        self._pool = MPSenderTxPool()
        acc = [create_account() for _ in range(2)]
        req_data = [dict(req_id="000", nonce=3, gas_price=30000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1]),
                    dict(req_id="001", nonce=1, gas_price=21000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1]),
                    dict(req_id="002", nonce=0, gas_price=40000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1]),
                    dict(req_id="003", nonce=2, gas_price=25000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1]),
                    dict(req_id="004", nonce=4, gas_price=25000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1])]
        self._requests = [get_transfer_mp_request(**req) for req in req_data]
        for request in self._requests:
            self._pool.add_tx(request)

    def test_done_tx(self):
        tx = self._pool.acquire_tx()
        self.assertTrue(self._pool.is_processing())
        self._pool.done_tx(tx)
        self.assertEqual(self._pool.get_queue_len(), 4)

    def test_drop_tx(self):
        tx = self._pool.acquire_tx()
        self.assertTrue(self._pool.is_processing())
        with self.assertRaises(AssertionError) as context:
            self._pool.drop_tx(tx)
        self.assertTrue('cannot drop processing tx' in str(context.exception))
        self.assertEqual(self._pool.get_queue_len(), 5)

        tx = self._pool._tx_nonce_queue[0]
        self._pool.drop_tx(tx)
        self.assertEqual(self._pool.get_queue_len(), 4)

    def test_cancel_tx(self):
        tx = self._pool.acquire_tx()
        self.assertTrue(self._pool.is_processing())
        self._pool.cancel_process_tx(tx, tx.neon_tx_exec_cfg)
        self.assertEqual(self._pool.get_queue_len(), 5)

    def test_take_out_txs_on_processing_pool(self):
        self._pool.acquire_tx()
        taken_out_txs = self._pool.take_out_tx_list()
        self.assertEqual(self._pool.get_queue_len(), 1)
        self.assertEqual(len(taken_out_txs), 4)

    def test_take_out_txs_on_non_processing_pool(self):
        taken_out_txs = self._pool.take_out_tx_list()
        self.assertEqual(self._pool.get_queue_len(), 0)
        self.assertEqual(len(taken_out_txs), 5)
