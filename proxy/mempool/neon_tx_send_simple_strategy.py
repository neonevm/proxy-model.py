from typing import List
from logged_groups import logged_group

from ..common_neon.solana_transaction import SolTx, SolLegacyTx, SolWrappedTx, SolTxReceipt
from ..common_neon.solana_tx_list_sender import SolTxListSender, SolTxSendState
from ..common_neon.solana_tx_error_parser import SolTxErrorParser
from ..common_neon.solana_neon_tx_receipt import SolTxMetaInfo, SolTxReceiptInfo
from ..common_neon.errors import BudgetExceededError
from ..common_neon.utils import NeonTxResultInfo
from ..common_neon.evm_log_decoder import decode_neon_tx_result

from ..mempool.neon_tx_send_base_strategy import BaseNeonTxStrategy
from ..mempool.neon_tx_send_strategy_base_stages import alt_strategy
from ..mempool.neon_tx_sender_ctx import NeonTxSendCtx


@logged_group("neon.MemPool")
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

    def _decode_neon_tx_result(self, tx: SolTx, tx_receipt: SolTxReceipt) -> None:
        if self._neon_tx_res.is_valid():
            return

        block_slot = tx_receipt['slot']
        tx_sig = SolTxSendState.decode_tx_sig(tx)
        tx_receipt_info = SolTxReceiptInfo(SolTxMetaInfo(block_slot, tx_sig, tx_receipt))
        for sol_neon_ix in tx_receipt_info.iter_sol_neon_ix():
            if decode_neon_tx_result(sol_neon_ix.iter_log(), self._strategy.ctx.neon_sig, self._neon_tx_res):
                self.debug(f'Got Neon tx result: {self._neon_tx_res}')
                break

    def _convert_state_to_tx_list(self, tx_status: SolTxSendState.Status,
                                  tx_state_list: List[SolTxSendState]) -> List[SolTx]:
        if self._neon_tx_res.is_valid():
            return []
        return super()._convert_state_to_tx_list(tx_status, tx_state_list)


class SimpleNeonTxStrategy(BaseNeonTxStrategy):
    name = 'TransactionExecuteFromInstruction'

    def __init__(self, ctx: NeonTxSendCtx):
        super().__init__(ctx)

    def _validate(self) -> bool:
        return (
            self._validate_notdeploy_tx() and
            self._validate_tx_has_chainid() and
            self._validate_evm_step_cnt() and
            self._validate_no_resize_iter_cnt()
        )

    def _validate_evm_step_cnt(self) -> bool:
        if self._ctx.emulated_evm_step_cnt < self._start_evm_step_cnt:
            return True
        self._validation_error = 'Too lot of EVM steps'
        return False

    def _validate_no_resize_iter_cnt(self) -> bool:
        if self._ctx.neon_tx_exec_cfg.resize_iter_cnt <= 0:
            return True
        self._validation_error_msg = 'Has additional account resize iterations'
        return False

    def _build_tx(self) -> SolLegacyTx:
        return BaseNeonTxStrategy._build_tx(self).add(
            self._ctx.ix_builder.make_tx_exec_from_data_ix()
        )

    def execute(self) -> NeonTxResultInfo:
        assert self.is_valid()

        tx_list = [SolWrappedTx(name=self.name, tx=self._build_tx())]
        tx_sender = SimpleNeonTxSender(self, self._ctx.solana, self._ctx.signer)
        tx_sender.send(tx_list)
        if not tx_sender.neon_tx_res.is_valid():
            raise BudgetExceededError()
        return tx_sender.neon_tx_res


@alt_strategy
class ALTSimpleNeonTxStrategy(SimpleNeonTxStrategy):
    pass
