import logging
from typing import List

from ..common_neon.solana_tx import SolTxReceipt, SolTx
from ..common_neon.solana_tx_legacy import SolLegacyTx
from ..common_neon.solana_tx_list_sender import SolTxListSender, SolTxSendState
from ..common_neon.solana_tx_error_parser import SolTxErrorParser
from ..common_neon.solana_neon_tx_receipt import SolTxReceiptInfo
from ..common_neon.errors import CUBudgetExceededError
from ..common_neon.utils import NeonTxResultInfo

from ..mempool.neon_tx_send_base_strategy import BaseNeonTxStrategy
from ..mempool.neon_tx_send_strategy_base_stages import alt_strategy
from ..mempool.neon_tx_sender_ctx import NeonTxSendCtx


LOG = logging.getLogger(__name__)


class SimpleNeonTxSender(SolTxListSender):
    def __init__(self, strategy: BaseNeonTxStrategy, *args, **kwargs):
        super().__init__(strategy.ctx.config, *args, **kwargs)
        self._strategy = strategy
        self._neon_tx_res = NeonTxResultInfo()

    @property
    def neon_tx_res(self) -> NeonTxResultInfo:
        return self._neon_tx_res

    def _decode_tx_status(self, tx: SolTx, tx_error_parser: SolTxErrorParser) -> SolTxSendState.Status:
        tx_status = super()._decode_tx_status(tx, tx_error_parser)
        if tx_status == SolTxSendState.Status.GoodReceipt:
            self._decode_neon_tx_result(tx, tx_error_parser.receipt)
        return tx_status

    def _decode_neon_tx_result(self, _: SolTx, tx_receipt: SolTxReceipt) -> None:
        if self._neon_tx_res.is_valid():
            return

        tx_receipt_info = SolTxReceiptInfo.from_tx(tx_receipt)
        for sol_neon_ix in tx_receipt_info.iter_sol_neon_ix():
            res = sol_neon_ix.neon_tx_return
            if res is not None:
                self._neon_tx_res.set_result(status=res.status, gas_used=res.gas_used)
                LOG.debug(f'Got Neon tx result: {self._neon_tx_res}')
                break

    def _convert_state_to_tx_list(self, tx_status: SolTxSendState.Status,
                                  tx_state_list: List[SolTxSendState]) -> List[SolTx]:
        if self._neon_tx_res.is_valid():
            return list()
        return super()._convert_state_to_tx_list(tx_status, tx_state_list)


class SimpleNeonTxStrategy(BaseNeonTxStrategy):
    name = 'TxExecFromData'

    def __init__(self, ctx: NeonTxSendCtx):
        super().__init__(ctx)

    def _validate(self) -> bool:
        return (
            # self._validate_notdeploy_tx() and
            # self._validate_evm_step_cnt() and  <- by default, try to execute the neon tx in one solana tx
            self._validate_tx_has_chainid() and
            self._validate_no_resize_iter_cnt()
        )

    def _validate_evm_step_cnt(self) -> bool:
        if self._ctx.emulated_evm_step_cnt < self._evm_step_cnt:
            return True
        self._validation_error_msg = 'Too lot of EVM steps'
        return False

    def _validate_no_resize_iter_cnt(self) -> bool:
        if self._ctx.neon_tx_exec_cfg.resize_iter_cnt <= 0:
            return True
        self._validation_error_msg = 'Has account resize iterations'
        return False

    def _build_tx(self) -> SolLegacyTx:
        return self._build_cu_tx(self._ctx.ix_builder.make_tx_exec_from_data_ix())

    def execute(self) -> NeonTxResultInfo:
        assert self.is_valid()

        tx_sender = SimpleNeonTxSender(self, self._ctx.solana, self._ctx.signer)
        tx_sender.send([self._build_tx()])
        if not tx_sender.neon_tx_res.is_valid():
            raise CUBudgetExceededError()
        return tx_sender.neon_tx_res


@alt_strategy
class ALTSimpleNeonTxStrategy(SimpleNeonTxStrategy):
    pass
