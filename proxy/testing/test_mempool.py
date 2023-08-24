from __future__ import annotations

import asyncio
import random
from random import randint

from eth_account.account import LocalAccount as NeonLocalAccount, Account as NeonAccount
from typing import Any, List, Dict, Optional, Union, Tuple, cast

import unittest
from unittest.mock import patch, MagicMock, call

from ..common_neon.config import Config
from ..common_neon.data import NeonTxExecCfg
from ..common_neon.solana_tx import SolPubKey
from ..common_neon.utils.eth_proto import NeonTx
from ..common_neon.elf_params import ElfParams
from ..common_neon.operator_resource_mng import OpResMng

from ..mempool.mempool_api import (
    MPRequest, OpResIdent,
    MPTxRequest, MPTxExecRequest, MPTxExecResult, MPTxExecResultCode, MPTxSendResult,
    MPGasPriceResult, MPSenderTxCntData, MPTxSendResultCode
)

from ..mempool.executor_mng import MPExecutorMng, IMPExecutorMngUser
from ..mempool.mempool import MemPool, MPTask, MPTxRequestList
from ..mempool.mempool_schedule import MPTxSchedule, MPSenderTxPool

from ..statistic.proxy_client import ProxyStatClient


def create_transfer_mp_request(*, req_id: str, nonce: int, gas: int, gas_price: int,
                               from_acct: Union[NeonAccount, NeonLocalAccount, None] = None,
                               to_acct: Union[NeonAccount, NeonLocalAccount, None] = None,
                               value: int = 0, data: bytes = b'') -> MPTxExecRequest:
    evm_program_id = SolPubKey.from_string('CmA9Z6FjioHJPpjT39QazZyhDRUdZy2ezwx4GiDdE2u2')

    if from_acct is None:
        from_acct = NeonAccount.create()

    if to_acct is None:
        to_acct = NeonAccount.create()

    to_addr = to_acct.address
    signed_tx_data = NeonAccount().sign_transaction(
        dict(nonce=nonce, chainId=111, gas=gas, gasPrice=gas_price, to=to_addr, value=value, data=data),
        from_acct.key
    )
    neon_tx = NeonTx.from_string(bytearray(signed_tx_data.rawTransaction))
    neon_tx_exec_cfg = NeonTxExecCfg()
    neon_tx_exec_cfg.set_state_tx_cnt(0)

    mp_tx_req = MPTxExecRequest.from_tx_req(
        MPTxRequest.from_neon_tx(
            req_id=req_id,
            neon_tx=neon_tx,
            neon_tx_exec_cfg=neon_tx_exec_cfg
        ),
        res_ident=OpResIdent(evm_program_id=evm_program_id, public_key='test', private_key=b'test'),
        elf_param_dict=ElfParams().elf_param_dict
    )
    return mp_tx_req


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


class FakeExecutorMsgUser(IMPExecutorMngUser):
    def on_executor_released(self, executor_id: int):
        pass


class MockMPExecutor(MPExecutorMng):
    def submit_mp_request(self, mp_req: MPRequest) -> MPTask:
        return self.create_mp_task(mp_req)

    @staticmethod
    def create_mp_task(mp_req: MPRequest) -> MPTask:
        mp_tx_req = cast(MPTxExecRequest, mp_req)
        neon_tx_cfg = mp_tx_req.neon_tx_exec_cfg
        done_status_list = [MPTxExecResultCode.Done, MPTxExecResultCode.Failed]
        done_status = random.choice(done_status_list)
        mp_tx_res = MPTxExecResult(done_status, neon_tx_cfg)
        aio_task = MockTask(mp_tx_res)
        return MPTask(1, aio_task, mp_req)

    def is_available(self) -> bool:
        return False

    def release_executor(self, executor_id: int):
        pass

    def __del__(self):
        pass


class MockResourceManager(OpResMng):
    def init_resource_list(self, res_ident_list: List[Union[OpResIdent, bytes]]) -> None:
        pass

    def get_resource(self, ident: str) -> OpResIdent:
        return OpResIdent(self._config.evm_program_id, public_key='test', private_key=b'test')

    def enable_resource(self, ident: OpResIdent) -> None:
        pass

    def release_resource(self, ident: str) -> None:
        pass

    def update_resource(self, neon_sig: str) -> None:
        pass

    def get_disabled_resource(self) -> Optional[OpResIdent]:
        return None


class FakeConfig(Config):
    @property
    def fuzz_fail_pct(self) -> int:
        return 0

    @property
    def gather_statistics(self) -> bool:
        return False

    @property
    def evm_program_id(self) -> SolPubKey:
        return SolPubKey.from_string('CmA9Z6FjioHJPpjT39QazZyhDRUdZy2ezwx4GiDdE2u2')

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
    async def asyncSetUp(self):
        config = FakeConfig()
        self._config = config

        stat_client = ProxyStatClient(config)
        self._stat_client = stat_client

        user = FakeExecutorMsgUser()
        self._user = user

        self._executor = MockMPExecutor(config, user, stat_client)
        self._op_res_mng = MockResourceManager(self._config, stat_client)
        self._mempool = MemPool(self._config, stat_client, self._op_res_mng, self._executor)

        price_result = MPGasPriceResult(
            is_const_gas_price=True,
            suggested_gas_price=1,
            min_executable_gas_price=1,
            min_acceptable_gas_price=1,
            last_update_mapping_sec=0,
            sol_price_usd=1000,
            neon_price_usd=25,
            sol_price_account=SolPubKey.new_unique(),
            neon_price_account=SolPubKey.new_unique(),
            gas_price_slippage=1,
            operator_fee=10,
            allow_underpriced_tx_wo_chainid=True,
            min_wo_chainid_acceptable_gas_price=1
        )
        task = MPTask(1, MockTask(result=None, is_done=False), MPRequest('1'))
        self._mempool._gas_price_task_loop._task = task
        self._mempool._gas_price_task_loop._gas_price = price_result

        self._mempool._op_res_init_task_loop._task = task
        self._mempool._op_res_get_list_task_loop._task = task

        self._mempool._elf_param_dict_task_loop._task = task
        self._mempool._state_tx_cnt_task_loop._task = task
        self._mempool._free_alt_queue_task_loop._task = task
        self._mempool._stuck_list_task_loop._task = task

    def _get_pending_tx_count(self, sender_address: str) -> int:
        sender_pool = self._mempool._tx_schedule._find_sender_pool(sender_address)
        return 0 if sender_pool is None else sender_pool.len_tx_nonce_queue

    @patch.object(MockMPExecutor, 'submit_mp_request', side_effect=MockMPExecutor.create_mp_task)
    @patch.object(MockMPExecutor, 'is_available', return_value=True)
    async def test_single_sender_single_tx(self, _: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if an enqueued mp_tx_request gets in effect"""
        mp_tx_req = create_transfer_mp_request(
            req_id='0000001', nonce=0, gas_price=30000, gas=987654321, value=1, data=b''
        )
        await self._mempool.enqueue_mp_request(mp_tx_req)
        await asyncio.sleep(0)

        submit_mp_request_mock.assert_called_once()
        submit_mp_request_mock.assert_called_with(mp_tx_req)

    @patch.object(MockMPExecutor, 'submit_mp_request', side_effect=MockMPExecutor.create_mp_task)
    @patch.object(MockMPExecutor, 'is_available', return_value=False)
    async def test_single_sender_couple_txs(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if an enqueued mp_tx_requests get in effect in the right order"""
        from_acct = NeonAccount.create()
        to_acct = NeonAccount.create()
        req_data_list = [
            dict(req_id='0000000', nonce=0, gas_price=3000, gas=9876543, value=1, from_acct=from_acct, to_acct=to_acct),
            dict(req_id='0000001', nonce=1, gas_price=2900, gas=9876543, value=1, from_acct=from_acct, to_acct=to_acct)
        ]
        req_list = await self._enqueue_requests(req_data_list)
        # await asyncio.sleep(0)
        submit_mp_request_mock.assert_not_called()
        is_available_mock.return_value = True
        self._mempool.on_executor_got_available(1)
        await asyncio.sleep(MemPool.check_task_timeout_sec * 2)
        submit_mp_request_mock.assert_has_calls([call(req_list[0])])

        self._update_state_tx_cnt([MPSenderTxCntData(sender=from_acct.address.lower(), state_tx_cnt=1)])
        self._mempool.on_executor_got_available(1)
        await asyncio.sleep(MemPool.check_task_timeout_sec * 2)
        submit_mp_request_mock.assert_has_calls([call(req_list[1])])

    @patch.object(MockMPExecutor, 'submit_mp_request', side_effect=MockMPExecutor.create_mp_task)
    @patch.object(MockMPExecutor, 'is_available', return_value=False)
    async def test_2_senders_4_txs(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if an enqueued mp_tx_request from different senders gets in effect in the right order"""
        acct_list = [NeonAccount.create() for _ in range(3)]
        req_data_list = [
            dict(req_id='000', nonce=0, gas_price=30000, gas=10, value=1, from_acct=acct_list[0], to_acct=acct_list[2]),
            dict(req_id='001', nonce=1, gas_price=21000, gas=10, value=1, from_acct=acct_list[0], to_acct=acct_list[2]),
            dict(req_id='002', nonce=0, gas_price=40000, gas=10, value=1, from_acct=acct_list[1], to_acct=acct_list[2]),
            dict(req_id='003', nonce=1, gas_price=25000, gas=10, value=1, from_acct=acct_list[1], to_acct=acct_list[2])
        ]
        req_list = await self._enqueue_requests(req_data_list)
        is_available_mock.return_value = True
        self._mempool.on_executor_got_available(1)
        await asyncio.sleep(MemPool.check_task_timeout_sec * 2)
        submit_mp_request_mock.assert_has_calls([call(req_list[2]), call(req_list[0])])

        self._update_state_tx_cnt([
            MPSenderTxCntData(sender=acct_list[0].address.lower(), state_tx_cnt=1),
            MPSenderTxCntData(sender=acct_list[1].address.lower(), state_tx_cnt=1)
        ])
        self._mempool.on_executor_got_available(1)
        await asyncio.sleep(MemPool.check_task_timeout_sec * 2)
        submit_mp_request_mock.assert_has_calls([call(req_list[3]), call(req_list[1])])

    @patch.object(MockMPExecutor, 'submit_mp_request')
    @patch.object(MockMPExecutor, 'is_available')
    async def test_mp_waits_for_previous_tx_done(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if an enqueued mp_tx_request waits for the previous one from the same sender"""
        is_available_mock.return_value = False
        acct_0 = NeonAccount.create()
        acct_1 = NeonAccount.create()
        req_data_list = [
            dict(req_id='000', nonce=0, gas_price=10000, gas=1000, value=1, from_acct=acct_0, to_acct=acct_1),
            dict(req_id='001', nonce=1, gas_price=10000, gas=1500, value=2, from_acct=acct_0, to_acct=acct_1)
        ]
        req_list = await self._enqueue_requests(req_data_list)
        is_available_mock.return_value = True
        submit_mp_request_mock.return_value = MPTask(1, MockTask(None, is_done=False), req_list[0])
        for i in range(2):
            await asyncio.sleep(MemPool.check_task_timeout_sec)
            self._mempool.on_executor_got_available(1)
        submit_mp_request_mock.assert_called_once_with(req_list[0])

    @patch.object(MockMPExecutor, 'submit_mp_request', side_effect=MockMPExecutor.create_mp_task)
    @patch.object(MockMPExecutor, 'is_available')
    async def test_subst_with_higher_gas_price(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if the transaction with the same nonce but the higher gas_price substitutes the current one"""
        from_acct = NeonAccount.create()
        base_req = create_transfer_mp_request(
            req_id='000', from_acct=from_acct, nonce=0, gas_price=30000, gas=987654321, value=1, data=b''
        )
        await self._mempool.schedule_mp_tx_request(base_req)
        subst_req = create_transfer_mp_request(
            req_id='001', from_acct=from_acct, nonce=0, gas_price=40000, gas=987654321, value=2, data=b''
        )
        await self._mempool.schedule_mp_tx_request(subst_req)
        is_available_mock.return_value = True
        self._mempool.on_executor_got_available(1)
        await asyncio.sleep(0)
        submit_mp_request_mock.assert_called_once()
        submit_mp_request_mock.assert_called_with(subst_req)

    @patch.object(MockMPExecutor, 'submit_mp_request', side_effect=MockMPExecutor.create_mp_task)
    @patch.object(MockMPExecutor, 'is_available')
    async def test_subst_with_lower_gas_price(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if the transaction with the same nonce but the lower gas_price is ignored"""
        from_acct = NeonAccount.create()
        base_req = create_transfer_mp_request(
            req_id='000', from_acct=from_acct, nonce=0, gas_price=40000, gas=987654321, value=1, data=b''
        )
        await self._mempool.schedule_mp_tx_request(base_req)
        subst_req = create_transfer_mp_request(
            req_id='001', from_acct=from_acct, nonce=0, gas_price=30000, gas=987654321, value=2, data=b''
        )
        await self._mempool.schedule_mp_tx_request(subst_req)
        is_available_mock.return_value = True
        self._mempool.on_executor_got_available(1)
        await asyncio.sleep(0)
        submit_mp_request_mock.assert_called_once()
        submit_mp_request_mock.assert_called_with(base_req)

    @patch.object(MockMPExecutor, 'is_available')
    async def test_check_pending_tx_count(self, is_available_mock: MagicMock):
        """Checks if all incoming mp_tx_requests those are not processed are counted as pending"""
        acct_list = [NeonAccount.create() for _ in range(3)]
        req_data_list = [
            dict(req_id='000', nonce=0, gas_price=30000, gas=10, value=1, from_acct=acct_list[0], to_acct=acct_list[2]),
            dict(req_id='001', nonce=1, gas_price=21000, gas=10, value=1, from_acct=acct_list[0], to_acct=acct_list[2]),
            dict(req_id='002', nonce=2, gas_price=25000, gas=10, value=1, from_acct=acct_list[1], to_acct=acct_list[2]),
            dict(req_id='003', nonce=0, gas_price=40000, gas=10, value=1, from_acct=acct_list[1], to_acct=acct_list[2]),
            dict(req_id='004', nonce=1, gas_price=25000, gas=10, value=1, from_acct=acct_list[1], to_acct=acct_list[2])
        ]
        req_list = await self._enqueue_requests(req_data_list)
        acct_0_count = self._get_pending_tx_count(req_list[0].sender_address)
        self.assertEqual(acct_0_count, 2)
        acct_1_count = self._get_pending_tx_count(req_list[3].sender_address)
        self.assertEqual(acct_1_count, 3)
        is_available_mock.return_value = True
        self._mempool.on_executor_got_available(1)
        await asyncio.sleep(MemPool.check_task_timeout_sec)
        acct_1_count = self._get_pending_tx_count(req_list[3].sender_address)
        self.assertEqual(acct_1_count, 2)

    @patch.object(MockMPExecutor, 'submit_mp_request', side_effect=MockMPExecutor.create_mp_task)
    @patch.object(MockMPExecutor, 'is_available')
    async def test_over_9000_transfers(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if all mp_tx_requests are processed by the MemPool"""
        acct_count = 1_000
        from_acct_count = 90
        nonce_count = 101
        acct_list = [NeonAccount.create() for _ in range(acct_count)]
        req_list: List[MPTxExecRequest] = list()

        for acct_idx in range(0, from_acct_count):
            for nonce in range(1, nonce_count):
                req = create_transfer_mp_request(
                    from_acct=acct_list[acct_idx], to_acct=acct_list[randint(0, acct_count-1)],
                    req_id=str(acct_idx) + '-' + str(nonce), nonce=nonce,
                    gas_price=randint(50000, 100000), gas=randint(4000, 10000)
                )
                req_list.append(req)

        random.shuffle(req_list)
        for req in req_list:
            await self._mempool.enqueue_mp_request(req)
        self.assertEqual(self._mempool._tx_schedule.tx_cnt, self._mempool._tx_schedule._capacity)
        self.assertEqual(submit_mp_request_mock.call_count, 0)

        is_available_mock.return_value = True
        for i in range(nonce_count):
            self._mempool.on_executor_got_available(1)
            await asyncio.sleep(self._mempool.check_task_timeout_sec * 2)

            nonce = i + 1
            update_tx_cnt_list: List[MPSenderTxCntData] = list()
            for sender in self._mempool._tx_schedule._sender_pool_dict.keys():
                update_tx_cnt_list.append(MPSenderTxCntData(sender=sender, state_tx_cnt=nonce))
            self._update_state_tx_cnt(update_tx_cnt_list)

        self.assertEqual(self._mempool._tx_schedule.tx_cnt, 0)
        self.assertEqual(submit_mp_request_mock.call_count, self._mempool._tx_schedule._capacity)

    async def _enqueue_requests(self, req_data_list: List[Dict[str, Any]]) -> MPTxRequestList:
        req_list = [create_transfer_mp_request(**req) for req in req_data_list]
        for req in req_list:
            await self._mempool.enqueue_mp_request(req)
        return req_list

    def _update_state_tx_cnt(self, sender_tx_cnt_list: List[MPSenderTxCntData]) -> None:
        for data in sender_tx_cnt_list:
            tx_pool = self._mempool._tx_schedule._find_sender_pool(data.sender)
            self.assertIsNotNone(tx_pool)
            self.assertNotEqual(tx_pool._actual_state, tx_pool.State.Processing)
            self.assertNotEqual(tx_pool.state, tx_pool.State.Processing)
        self._mempool._tx_schedule.set_sender_state_tx_cnt_list(sender_tx_cnt_list)


class TestMPSchedule(unittest.TestCase):
    @staticmethod
    def _get_pending_tx_count(schedule: MPTxSchedule, sender_address: str) -> int:
        sender_pool = schedule._find_sender_pool(sender_address)
        return 0 if sender_pool is None else sender_pool.len_tx_nonce_queue

    @staticmethod
    def _acquire_top_tx(schedule: MPTxSchedule) -> Optional[MPTxRequest]:
        tx = schedule.peek_top_tx()
        if tx is None:
            return None
        return schedule.acquire_tx(tx)

    def test_capacity_oversized_simple(self):
        """Checks if mp_schedule gets oversized in simple way"""
        schedule = MPTxSchedule(5)
        acct_list = [NeonAccount.create() for _ in range(3)]
        req_data_list = [
            dict(req_id='000', nonce=1, gas_price=6000, gas=10, value=1, from_acct=acct_list[0], to_acct=acct_list[1]),
            dict(req_id='001', nonce=0, gas_price=6000, gas=10, value=1, from_acct=acct_list[0], to_acct=acct_list[1]),
            dict(req_id='002', nonce=1, gas_price=4000, gas=10, value=1, from_acct=acct_list[1], to_acct=acct_list[2]),
            dict(req_id='003', nonce=1, gas_price=7000, gas=10, value=1, from_acct=acct_list[2], to_acct=acct_list[1]),
            dict(req_id='004', nonce=0, gas_price=2500, gas=10, value=1, from_acct=acct_list[1], to_acct=acct_list[2]),
            dict(req_id='005', nonce=2, gas_price=5000, gas=10, value=1, from_acct=acct_list[2], to_acct=acct_list[1]),
            dict(req_id='006', nonce=0, gas_price=5000, gas=10, value=1, from_acct=acct_list[2], to_acct=acct_list[1])
        ]
        req_list = [create_transfer_mp_request(**req) for req in req_data_list]
        for req in req_list[0:5]:
            schedule.add_tx(req)

        self.assertIs(self._acquire_top_tx(schedule), req_list[1])
        self.assertIs(self._acquire_top_tx(schedule), req_list[4])
        self.assertIs(self._acquire_top_tx(schedule), None)
        for request in req_list[5:]:
            schedule.add_tx(request)
        self.assertEqual(acct_list[2].address.lower(), schedule._sender_pool_queue[0].sender_address)
        self.assertIs(req_list[3], schedule._sender_pool_queue[0]._tx_nonce_queue[0])
        self.assertEqual(5, schedule.tx_cnt)
        self.assertEqual(1, len(schedule._sender_pool_queue))
        self.assertEqual(2, self._get_pending_tx_count(schedule, acct_list[0].address.lower()))
        self.assertEqual(1, self._get_pending_tx_count(schedule, acct_list[1].address.lower()))
        self.assertEqual(2, self._get_pending_tx_count(schedule, acct_list[2].address.lower()))

    def test_capacity_oversized(self):
        """Checks if mp_schedule doesn't get oversized with a quite big set of mp_tx_requests"""
        acc_count_max = 20
        from_acc_count = 10
        nonce_count = 1000
        mp_schedule_capacity = 4000
        schedule = MPTxSchedule(mp_schedule_capacity)
        acct_list = [NeonAccount.create() for _ in range(acc_count_max)]
        req_list: List[MPTxExecRequest] = list()
        for acc_idx in range(0, from_acc_count):
            for nonce in range(0, nonce_count):
                req = create_transfer_mp_request(
                    from_acct=acct_list[acc_idx], to_acct=acct_list[randint(0, acc_count_max - 1)],
                    req_id=str(acc_idx) + '-' + str(nonce), nonce=nonce_count - nonce - 1,
                    gas_price=randint(50000, 100000), gas=randint(4000, 10000)
                )
                req_list.append(req)

        random.shuffle(req_list)
        for req in req_list:
            schedule.add_tx(req)
        self.assertEqual(mp_schedule_capacity, schedule.tx_cnt)

    def test_take_out_txs(self):
        schedule = MPTxSchedule(100)
        acct_list = [NeonAccount.create() for _ in range(3)]
        req_data_list = [
            dict(req_id='000', nonce=0, gas_price=60000, gas=10, value=1, from_acct=acct_list[0], to_acct=acct_list[1]),
            dict(req_id='001', nonce=1, gas_price=60000, gas=10, value=1, from_acct=acct_list[0], to_acct=acct_list[1]),
            dict(req_id='002', nonce=0, gas_price=40000, gas=10, value=1, from_acct=acct_list[1], to_acct=acct_list[2]),
            dict(req_id='003', nonce=0, gas_price=70000, gas=10, value=1, from_acct=acct_list[2], to_acct=acct_list[1]),
            dict(req_id='004', nonce=1, gas_price=25000, gas=10, value=1, from_acct=acct_list[1], to_acct=acct_list[2]),
            dict(req_id='005', nonce=1, gas_price=50000, gas=10, value=1, from_acct=acct_list[2], to_acct=acct_list[1]),
            dict(req_id='006', nonce=2, gas_price=50000, gas=10, value=1, from_acct=acct_list[2], to_acct=acct_list[1])
        ]
        req_list = [create_transfer_mp_request(**req) for req in req_data_list]
        for req in req_list:
            schedule.add_tx(req)
        self.assertEqual(len(schedule._sender_pool_dict), 3)
        self.assertEqual(len(schedule._sender_pool_queue), 3)
        acct0, acct1, acct2 = acct_list[0].address.lower(), acct_list[1].address.lower(), acct_list[2].address.lower()
        awaiting_dict = {acct0: 2, acct1: 2, acct2: 3}

        for sender_addr, tx_list in schedule.iter_taking_out_tx_list:
            self.assertEqual(awaiting_dict[sender_addr], len(tx_list))

        self.assertEqual(self._get_pending_tx_count(schedule, acct0), 0)
        self.assertEqual(self._get_pending_tx_count(schedule, acct1), 0)
        self.assertEqual(self._get_pending_tx_count(schedule, acct2), 0)

    def test_tx_lifecycle(self):
        def _tx_is_been_scheduled():
            self.assertEqual(len(schedule._sender_pool_dict), 1)

            tx_pool = schedule._find_sender_pool(req.sender_address)
            self.assertIsNotNone(tx_pool)
            self.assertEqual(tx_pool.top_tx.sig, req.sig)
            self.assertEqual(len(schedule._sender_pool_queue), 1)
            self.assertIn(tx_pool, schedule._sender_pool_queue)

            self.assertEqual(len(schedule._tx_dict._tx_hash_dict), 1)
            self.assertEqual(schedule._tx_dict._tx_hash_dict[req.sig].sender_address, req.sender_address)

            self.assertEqual(len(schedule._tx_dict._tx_sender_nonce_dict), 1)
            sender_nonce = schedule._tx_dict._sender_nonce(req)
            self.assertEqual(schedule._tx_dict._tx_sender_nonce_dict[sender_nonce].sig, req.sig)

            self.assertEqual(len(schedule._tx_dict._tx_gas_price_queue), 1)
            self.assertIn(req, schedule._tx_dict._tx_gas_price_queue)

        def _tx_is_been_processed():
            self.assertEqual(len(schedule._sender_pool_dict), 1)
            self.assertEqual(len(schedule._sender_pool_queue), 0)
            self.assertEqual(len(schedule._tx_dict._tx_hash_dict), 1)
            self.assertEqual(len(schedule._tx_dict._tx_sender_nonce_dict), 1)
            self.assertEqual(len(schedule._tx_dict._tx_gas_price_queue), 0)

        schedule = MPTxSchedule(100)
        acct_list = [NeonAccount.create() for _ in range(2)]
        req = create_transfer_mp_request(
            req_id='000', nonce=0, gas_price=600, gas=10, value=1, from_acct=acct_list[0], to_acct=acct_list[1]
        )
        schedule.add_tx(req)
        _tx_is_been_scheduled()

        tx = self._acquire_top_tx(schedule)
        self.assertEqual(tx.sig, req.sig)
        _tx_is_been_processed()

        schedule.set_sender_state_tx_cnt_list([MPSenderTxCntData(sender=tx.sender_address, state_tx_cnt=tx.nonce + 1)])
        _tx_is_been_processed()

        schedule.cancel_tx(tx)
        _tx_is_been_scheduled()

        tx = self._acquire_top_tx(schedule)
        self.assertEqual(tx.sig, req.sig)
        _tx_is_been_processed()

        schedule.done_tx(tx)
        self.assertEqual(len(schedule._sender_pool_dict), 0)
        self.assertEqual(len(schedule._sender_pool_queue), 0)
        self.assertEqual(len(schedule._tx_dict._tx_hash_dict), 0)
        self.assertEqual(len(schedule._tx_dict._tx_sender_nonce_dict), 0)
        self.assertEqual(len(schedule._tx_dict._tx_gas_price_queue), 0)

    def test_add_tx(self):
        def _copy_req(src: dict, **args) -> dict:
            dst = src.copy()
            dst.update(**args)
            return dst

        def _add_tx(src: dict, **args) -> Tuple[MPTxRequest, MPTxSendResult]:
            dst_data = _copy_req(src, **args)
            dst_req = create_transfer_mp_request(**dst_data)
            return dst_req, schedule.add_tx(dst_req)

        mp_capacity = 10
        schedule = MPTxSchedule(mp_capacity)
        acct1, acct2 = NeonAccount.create(), NeonAccount.create()

        req_data = dict(gas_price=1000, gas=11, value=1, from_acct=acct2, to_acct=acct1)
        for req in range(0, mp_capacity - 1):
            req, res = _add_tx(req_data, nonce=req, req_id=str(req))
            self.assertEqual(res.code, MPTxSendResultCode.Success)
            self.assertIsNone(res.state_tx_cnt)

        req_data = dict(gas_price=1100, nonce=10, gas=11, value=1, from_acct=acct1, to_acct=acct2)
        req, res = _add_tx(req_data, req_id='base')
        self.assertEqual(res.code, MPTxSendResultCode.Success)
        self.assertIsNone(res.state_tx_cnt)
        self.assertIn(req.sig, schedule._tx_dict._tx_hash_dict)

        res = schedule.add_tx(req)
        self.assertEqual(res.code, MPTxSendResultCode.AlreadyKnown)
        self.assertIsNone(res.state_tx_cnt)

        low_req, res = _add_tx(req_data, req_id='low', gas_price=req.gas_price - 1)
        self.assertEqual(res.code, MPTxSendResultCode.Underprice)
        self.assertIsNone(res.state_tx_cnt)
        self.assertNotIn(low_req.sig, schedule._tx_dict._tx_hash_dict)

        global_low_req, res = _add_tx(req_data, req_id='global-low', gas_price=1, nonce=req.nonce - 1)
        self.assertEqual(res.code, MPTxSendResultCode.Underprice)
        self.assertIsNone(res.state_tx_cnt)
        self.assertNotIn(global_low_req.sig, schedule._tx_dict._tx_hash_dict)

        new_req, res = _add_tx(req_data, req_id='high-gas-price', gas_price=req.gas_price + 1)
        self.assertEqual(res.code, MPTxSendResultCode.Success)
        self.assertIsNone(res.state_tx_cnt)
        self.assertNotIn(req.sig, schedule._tx_dict._tx_hash_dict)
        self.assertIn(new_req.sig, schedule._tx_dict._tx_hash_dict)

        schedule.set_sender_state_tx_cnt_list([MPSenderTxCntData(sender=req.sender_address, state_tx_cnt=req.nonce)])
        tx = self._acquire_top_tx(schedule)
        self.assertEqual(new_req.sig, tx.sig)

        processing_req, res = _add_tx(req_data, req_id='processing', gas_price=tx.gas_price + 1)
        self.assertEqual(res.code, MPTxSendResultCode.NonceTooLow)
        self.assertEqual(res.state_tx_cnt, tx.nonce + 1)

        req, res = _add_tx(req_data, req_id='new-nonce', nonce=tx.nonce + 1)
        self.assertEqual(res.code, MPTxSendResultCode.Success)
        self.assertIsNone(res.state_tx_cnt)
        self.assertIn(req.sig, schedule._tx_dict._tx_hash_dict)
        self.assertIn(tx.sig, schedule._tx_dict._tx_hash_dict)

        schedule.done_tx(tx)
        self.assertIn(req.sig, schedule._tx_dict._tx_hash_dict)
        self.assertNotIn(tx.sig, schedule._tx_dict._tx_hash_dict)


class TestMPSenderTxPool(unittest.TestCase):
    def setUp(self) -> None:
        self._pool = MPSenderTxPool('test_sender')
        acct_list = [NeonAccount.create() for _ in range(2)]
        req_data_list = [
            dict(req_id='000', nonce=3, gas_price=30000, gas=10, value=1, from_acct=acct_list[0], to_acct=acct_list[1]),
            dict(req_id='001', nonce=1, gas_price=21000, gas=10, value=1, from_acct=acct_list[0], to_acct=acct_list[1]),
            dict(req_id='002', nonce=0, gas_price=40000, gas=10, value=1, from_acct=acct_list[0], to_acct=acct_list[1]),
            dict(req_id='003', nonce=2, gas_price=25000, gas=10, value=1, from_acct=acct_list[0], to_acct=acct_list[1]),
            dict(req_id='004', nonce=4, gas_price=25000, gas=10, value=1, from_acct=acct_list[0], to_acct=acct_list[1])
        ]
        req_list = [create_transfer_mp_request(**req) for req in req_data_list]
        for req in req_list:
            self._pool.add_tx(req)

    def _acquire_top_tx(self) -> Optional[MPTxRequest]:
        top_tx = self._pool.top_tx
        return self._pool.acquire_tx(top_tx)

    def test_done_tx(self):
        tx = self._acquire_top_tx()
        self.assertEqual(self._pool._actual_state, self._pool.State.Processing)
        self.assertEqual(self._pool.state, self._pool.State.Processing)
        self._pool.done_tx(tx)
        self.assertEqual(self._pool.len_tx_nonce_queue, 4)

    def test_drop_tx(self):
        tx = self._acquire_top_tx()
        self.assertEqual(self._pool._actual_state, self._pool.State.Processing)
        self.assertEqual(self._pool.state, self._pool.State.Processing)
        with self.assertRaises(AssertionError) as context:
            self._pool.drop_tx(tx)
        self.assertTrue('cannot drop processing tx' in str(context.exception))
        self.assertEqual(self._pool.len_tx_nonce_queue, 5)

        tx = self._pool._tx_nonce_queue[0]
        self._pool.drop_tx(tx)
        self.assertEqual(self._pool.len_tx_nonce_queue, 4)

    def test_cancel_tx(self):
        tx = self._acquire_top_tx()
        self.assertEqual(self._pool._actual_state, self._pool.State.Processing)
        self.assertEqual(self._pool.state, self._pool.State.Processing)
        self._pool.cancel_process_tx(tx)
        self.assertEqual(self._pool.len_tx_nonce_queue, 5)

    def test_take_out_txs_on_processing_pool(self):
        self._acquire_top_tx()
        taken_out_tx_list = self._pool.take_out_tx_list()
        self.assertEqual(self._pool.len_tx_nonce_queue, 1)
        self.assertEqual(len(taken_out_tx_list), 4)

    def test_take_out_txs_on_non_processing_pool(self):
        taken_out_tx_list = self._pool.take_out_tx_list()
        self.assertEqual(self._pool.len_tx_nonce_queue, 0)
        self.assertEqual(len(taken_out_tx_list), 5)
