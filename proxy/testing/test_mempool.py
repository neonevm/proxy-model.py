from __future__ import annotations

import asyncio
import logging
from typing import Tuple
from asyncio import Task

import unittest
from unittest.mock import patch, MagicMock

from ..mempool.mempool import MemPool, IMPExecutor
from ..mempool.mempool_api import NeonTxExecCfg, MPRequest, MPTxRequest

from ..common_neon.eth_proto import Trx as NeonTx

neon_logger = logging.getLogger("neon")
neon_logger.setLevel(logging.ERROR)


class MockMPExecutor(IMPExecutor):

    def submit_mp_request(self, mp_reqeust: MPRequest) -> Tuple[int, Task]:
        pass

    def is_available(self) -> bool:
        return True

    def on_no_liquidity(self, resource_id: int):
        pass

    def release_resource(self, resource_id: int):
        pass


class Test(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.executor = MockMPExecutor()
        self.mempool = MemPool(self.executor)

    @patch.object(MockMPExecutor, "submit_mp_request")
    async def test_single_sender_txs(self, submit_mp_request_mock: MagicMock):
        neon_tx = NeonTx.fromString(bytearray.fromhex(
            'f8678080843ade68b194f0dafe87532d4373453b2555c644390e1b99e84c8459682f0080820102a00193e1966a82c5597942370980fb78080901ca86eb3c1b25ec600b2760cfcc94a03efcc1169e161f9a148fd4586e0bcf880648ca74075bfa7a9acc8800614fc9ff'))

        tx_cfg = NeonTxExecCfg(is_underpriced_tx_without_chainid=False, steps_executed=100)
        mp_tx_request = MPTxRequest(signature="asdf", neon_tx=neon_tx, neon_tx_exec_cfg=tx_cfg, emulating_result=dict(),
                                    req_id="test_rq_1")
        await self.mempool._on_send_tx_request(mp_tx_request)
        await asyncio.sleep(0)
        submit_mp_request_mock.assert_called_once()
        submit_mp_request_mock.assert_called_with(mp_tx_request)

    async def test_test(self):
        pass
