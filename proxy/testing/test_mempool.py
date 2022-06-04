from __future__ import annotations

import asyncio
import logging

import secrets

from web3 import Web3, Account
from typing import Tuple, Any

import unittest
from unittest.mock import patch, MagicMock, call


from ..mempool.mempool import MemPool, IMPExecutor
from ..mempool.mempool_api import NeonTxExecCfg, MPRequest, MPTxRequest
from ..common_neon.eth_proto import Trx as NeonTx

from ..mempool.mempool_api import MPTxResult, MPResultCode


class MockTask:

    def __init__(self, result: Any):
        self._result = result

    def done(self):
        return True

    def result(self):
        return self._result

    def exception(self):
        return None


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
        neon_logger.setLevel(logging.ERROR)

    async def asyncSetUp(self):
        self.executor = MockMPExecutor()
        self.mempool = MemPool(self.executor)

    @patch.object(MockMPExecutor, "submit_mp_request")
    async def test_single_sender_single_tx(self, submit_mp_request_mock: MagicMock):
        submit_mp_request_mock.return_value = 1, MockTask(MPTxResult(MPResultCode.Done, None))
        mp_tx_request = self.get_transfer_mp_request(req_id="0000001", nonce=0, gasPrice=30000, gas=987654321, value=1, data=b'')
        await self.mempool._on_send_tx_request(mp_tx_request)
        await self.mempool._kick_tx_queue()
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
        req_nonce_0 = self.get_transfer_mp_request(req_id="0000000", nonce=0, gasPrice=30000, gas=987654321, value=1, from_acc=from_acc, to_acc=to_acc)
        req_nonce_1 = self.get_transfer_mp_request(req_id="0000001", nonce=1, gasPrice=29000, gas=987654321, value=1, from_acc=from_acc, to_acc=to_acc)

        await self.mempool._on_send_tx_request(req_nonce_1)
        await self.mempool._on_send_tx_request(req_nonce_0)
        await asyncio.sleep(0)
        submit_mp_request_mock.assert_not_called()
        is_available_mock.return_value = True
        # TODO: get rid of it. MemPool should work without kicking the queue. It's the test case as it is.
        await self.mempool._kick_tx_queue()
        await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC)

        submit_mp_request_mock.assert_has_calls([call(req_nonce_0), call(req_nonce_1)])

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    async def test_2_senders_4_txs(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        submit_mp_request_mock.return_value = 1, MockTask(MPTxResult(MPResultCode.Done, None))
        is_available_mock.return_value = False
        acc_0 = self.create_account()
        acc_1 = self.create_account()
        acc_3 = self.create_account()
        requests = [dict(req_id="000", nonce=0, gasPrice=30000, gas=1000, value=1, from_acc=acc_0, to_acc=acc_3),
                    dict(req_id="001", nonce=1, gasPrice=21000, gas=1000, value=1, from_acc=acc_0, to_acc=acc_3),
                    dict(req_id="002", nonce=0, gasPrice=40000, gas=1000, value=1, from_acc=acc_1, to_acc=acc_3),
                    dict(req_id="003", nonce=1, gasPrice=25000, gas=1000, value=1, from_acc=acc_1, to_acc=acc_3)]
        requests = [self.get_transfer_mp_request(**req) for req in requests]
        for req in requests:
            await self.mempool._on_send_tx_request(req)
        is_available_mock.return_value = True
        await self.mempool._kick_tx_queue()
        await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC * 3)

        submit_mp_request_mock.assert_has_calls([call(requests[2]), call(requests[0]), call(requests[3]), call(requests[1])])

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    async def test_subst_with_higher_gas_price(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        submit_mp_request_mock.return_value = 1, MockTask(MPTxResult(MPResultCode.Done, None))
        is_available_mock.return_value = False
        base_request = self.get_transfer_mp_request(req_id="0", nonce=0, gasPrice=30000, gas=987654321, value=1, data=b'')
        await self.mempool._on_send_tx_request(base_request)
        subst_request = self.get_transfer_mp_request(req_id="1", nonce=0, gasPrice=40000, gas=987654321, value=2, data=b'')
        await self.mempool._on_send_tx_request(subst_request)
        is_available_mock.return_value = True
        await self.mempool._kick_tx_queue()
        await asyncio.sleep(0)
        submit_mp_request_mock.assert_called_once()
        submit_mp_request_mock.assert_called_with(subst_request)

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    async def test_subst_with_lower_gas_price(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        submit_mp_request_mock.return_value = 1, MockTask(MPTxResult(MPResultCode.Done, None))
        is_available_mock.return_value = False
        base_request = self.get_transfer_mp_request(req_id="0", nonce=0, gasPrice=40000, gas=987654321, value=1, data=b'')
        await self.mempool._on_send_tx_request(base_request)
        subst_request = self.get_transfer_mp_request(req_id="1", nonce=0, gasPrice=30000, gas=987654321, value=2, data=b'')
        await self.mempool._on_send_tx_request(subst_request)
        is_available_mock.return_value = True
        await self.mempool._kick_tx_queue()
        await asyncio.sleep(0)
        submit_mp_request_mock.assert_called_once()
        submit_mp_request_mock.assert_called_with(base_request)

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
