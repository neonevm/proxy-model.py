from __future__ import annotations

import asyncio
import logging

import secrets

from web3 import Web3, Account
from typing import Tuple, Any, List, Dict

import unittest
from unittest.mock import patch, MagicMock, call


from ..mempool.mempool import MemPool, IMPExecutor
from ..mempool.mempool_api import NeonTxExecCfg, MPRequest, MPTxRequest
from ..common_neon.eth_proto import Trx as NeonTx

from ..mempool.mempool_api import MPTxResult, MPResultCode


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

    def submit_mp_request(self, mp_reqeust: MPRequest) -> Tuple[int, MockTask]:
        pass

    def is_available(self) -> bool:
        return True

    def on_no_liquidity(self, resource_id: int):
        pass

    def release_resource(self, resource_id: int):
        pass


class Test(unittest.IsolatedAsyncioTestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.turn_logger_off()
        cls.w3 = Web3()

    @classmethod
    def turn_logger_off(cls) -> None:
        neon_logger = logging.getLogger("neon")
        neon_logger.setLevel(logging.DEBUG)

    async def asyncSetUp(self):
        self.executor = MockMPExecutor()
        self.mempool = MemPool(self.executor)

    @patch.object(MockMPExecutor, "submit_mp_request")
    async def test_single_sender_single_tx(self, submit_mp_request_mock: MagicMock):
        submit_mp_request_mock.return_value = 1, MockTask(MPTxResult(MPResultCode.Done, None))
        mp_tx_request = self.get_transfer_mp_request(req_id="0000001", nonce=0, gasPrice=30000, gas=987654321, value=1, data=b'')
        await self.mempool.enqueue_mp_request(mp_tx_request)
        await asyncio.sleep(0)

        submit_mp_request_mock.assert_called_once()
        submit_mp_request_mock.assert_called_with(mp_tx_request)

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    async def test_single_sender_couple_txs(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        submit_mp_request_mock.return_value = 1, MockTask(MPTxResult(MPResultCode.Done, None))
        is_available_mock.return_value = False
        from_acc = self.create_account()
        to_acc = self.create_account()
        req_data = [dict(req_id="0000000", nonce=0, gasPrice=30000, gas=987654321, value=1, from_acc=from_acc, to_acc=to_acc),
                    dict(req_id="0000001", nonce=1, gasPrice=29000, gas=987654321, value=1, from_acc=from_acc, to_acc=to_acc)]
        requests = await self._enqueue_requests(req_data)
        await asyncio.sleep(0)
        submit_mp_request_mock.assert_not_called()
        is_available_mock.return_value = True
        self.mempool.on_resource_got_available(1)
        await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC * 5)

        submit_mp_request_mock.assert_has_calls([call(requests[0]), call(requests[1])])

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    async def test_2_senders_4_txs(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        submit_mp_request_mock.return_value = 1, MockTask(MPTxResult(MPResultCode.Done, None))
        is_available_mock.return_value = False
        acc = [self.create_account() for i in range(3)]
        req_data = [dict(req_id="000", nonce=0, gasPrice=30000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[2]),
                    dict(req_id="001", nonce=1, gasPrice=21000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[2]),
                    dict(req_id="002", nonce=0, gasPrice=40000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2]),
                    dict(req_id="003", nonce=1, gasPrice=25000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2])]
        requests = await self._enqueue_requests(req_data)
        is_available_mock.return_value = True
        self.mempool.on_resource_got_available(1)
        await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC * 2)

        submit_mp_request_mock.assert_has_calls([call(requests[2]), call(requests[0]), call(requests[3]), call(requests[1])])

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    async def test_mp_waits_for_previous_tx_done(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        submit_mp_request_mock.return_value = 1, MockTask(None, is_done=False)
        is_available_mock.return_value = False
        acc_0 = self.create_account()
        acc_1 = self.create_account()
        req_data = [dict(req_id="000", nonce=0, gasPrice=10000, gas=1000, value=1, from_acc=acc_0, to_acc=acc_1),
                    dict(req_id="001", nonce=1, gasPrice=10000, gas=1500, value=2, from_acc=acc_0, to_acc=acc_1)]
        requests = await self._enqueue_requests(req_data)
        is_available_mock.return_value = True
        for i in range(2):
            await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC)
            self.mempool.on_resource_got_available(1)
        submit_mp_request_mock.assert_called_once_with(requests[0])

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    async def test_subst_with_higher_gas_price(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        submit_mp_request_mock.return_value = 1, MockTask(MPTxResult(MPResultCode.Done, None))
        is_available_mock.return_value = False
        from_acc = self.create_account()
        base_request = self.get_transfer_mp_request(req_id="0", from_acc=from_acc, nonce=0, gasPrice=30000, gas=987654321, value=1, data=b'')
        await self.mempool._schedule_mp_tx_request(base_request)
        subst_request = self.get_transfer_mp_request(req_id="1", from_acc=from_acc, nonce=0, gasPrice=40000, gas=987654321, value=2, data=b'')
        await self.mempool._schedule_mp_tx_request(subst_request)
        is_available_mock.return_value = True
        self.mempool.on_resource_got_available(1)
        await asyncio.sleep(0)
        submit_mp_request_mock.assert_called_once()
        submit_mp_request_mock.assert_called_with(subst_request)

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    async def test_subst_with_lower_gas_price(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        submit_mp_request_mock.return_value = 1, MockTask(MPTxResult(MPResultCode.Done, None))
        is_available_mock.return_value = False
        from_acc = self.create_account()
        base_request = self.get_transfer_mp_request(req_id="0", from_acc=from_acc, nonce=0, gasPrice=40000, gas=987654321, value=1, data=b'')
        await self.mempool._schedule_mp_tx_request(base_request)
        subst_request = self.get_transfer_mp_request(req_id="1", from_acc=from_acc, nonce=0, gasPrice=30000, gas=987654321, value=2, data=b'')
        await self.mempool._schedule_mp_tx_request(subst_request)
        is_available_mock.return_value = True
        self.mempool.on_resource_got_available(1)
        await asyncio.sleep(0)
        submit_mp_request_mock.assert_called_once()
        submit_mp_request_mock.assert_called_with(base_request)

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    async def test_check_pending_tx_count(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        submit_mp_request_mock.return_value = 1, MockTask(MPTxResult(MPResultCode.Done, None))
        is_available_mock.return_value = False
        acc = [self.create_account() for i in range(3)]
        req_data = [dict(req_id="000", nonce=0, gasPrice=30000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[2]),
                    dict(req_id="001", nonce=1, gasPrice=21000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[2]),
                    dict(req_id="002", nonce=0, gasPrice=40000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2]),
                    dict(req_id="003", nonce=1, gasPrice=25000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2]),
                    dict(req_id="004", nonce=2, gasPrice=25000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2])]
        requests = await self._enqueue_requests(req_data)
        acc_0_count = self.mempool.get_pending_trx_count(requests[0].sender_address)
        self.assertEqual(acc_0_count, 2)
        acc_1_count = self.mempool.get_pending_trx_count(requests[3].sender_address)
        self.assertEqual(acc_1_count, 3)
        is_available_mock.return_value = True
        self.mempool.on_resource_got_available(1)
        await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC)
        acc_1_count = self.mempool.get_pending_trx_count(requests[3].sender_address)
        self.assertEqual(acc_1_count, 2)

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    def test_over_9000_transfers(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        pass

    async def _enqueue_requests(self, req_data: List[Dict[str, Any]]) -> List[MPTxRequest]:
        requests = [self.get_transfer_mp_request(**req) for req in req_data]
        for req in requests:
            await self.mempool._schedule_mp_tx_request(req)
        return requests

    def create_account(self) -> Account:
        priv = secrets.token_hex(32)
        private_key = "0x" + priv
        acct = Account.from_key(private_key)
        return acct

    def get_transfer_mp_request(self, *, req_id: str, nonce: int, gas: int, gasPrice: int, from_acc: Account = None,
                                         to_acc: Account = None, value: int = 0, data: bytes = b'') -> MPTxRequest:
        if from_acc is None:
            from_acc = self.create_account()

        if to_acc is None:
            to_acc = self.create_account()
        to_addr = to_acc.address

        signed_tx_data = self.w3.eth.account.sign_transaction(
            dict(nonce=nonce, chainId=111, gas=gas, gasPrice=gasPrice, to=to_addr, value=value, data=data),
            from_acc.key
        )
        signature = signed_tx_data.hash.hex()
        neon_tx = NeonTx.fromString(bytearray(signed_tx_data.rawTransaction))
        tx_cfg = NeonTxExecCfg(is_underpriced_tx_without_chainid=False, steps_executed=100)
        mp_tx_request = MPTxRequest(req_id=req_id, signature=signature, neon_tx=neon_tx, neon_tx_exec_cfg=tx_cfg,
                                    emulating_result=dict())
        return mp_tx_request
