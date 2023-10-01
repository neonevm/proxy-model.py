import abc
import logging

from typing import Optional, List, Generator, cast

from ..common_neon.elf_params import ElfParams
from ..common_neon.solana_neon_tx_receipt import SolNeonTxReceiptInfo, SolNeonIxReceiptInfo
from ..common_neon.solana_tx import SolTx, SolTxIx
from ..common_neon.solana_tx_legacy import SolLegacyTx
from ..common_neon.solana_tx_list_sender import SolTxListSender, SolTxSendState
from ..common_neon.neon_tx_result_info import NeonTxResultInfo
from ..common_neon.utils import cached_property

from ..mempool.neon_tx_sender_ctx import NeonTxSendCtx


LOG = logging.getLogger(__name__)


class BaseNeonTxPrepStage(abc.ABC):
    def __init__(self, ctx: NeonTxSendCtx):
        self._ctx = ctx

    @abc.abstractmethod
    def complete_init(self) -> None:
        pass

    @abc.abstractmethod
    def get_tx_name_list(self) -> List[str]:
        pass

    @abc.abstractmethod
    def build_tx_list(self) -> List[List[SolTx]]:
        pass

    @abc.abstractmethod
    def update_after_emulate(self) -> None:
        pass


class BaseNeonTxStrategy(abc.ABC):
    name = 'UNKNOWN STRATEGY'

    def __init__(self, ctx: NeonTxSendCtx):
        self._validation_error_msg: Optional[str] = None
        self._prep_stage_list: List[BaseNeonTxPrepStage] = list()
        self._ctx = ctx
        self._evm_step_cnt = ElfParams().neon_evm_steps

    @property
    def ctx(self) -> NeonTxSendCtx:
        return self._ctx

    @property
    def validation_error_msg(self) -> str:
        assert not self.is_valid()
        return cast(str, self._validation_error_msg)

    def is_valid(self) -> bool:
        return self._validation_error_msg is None

    def validate(self) -> bool:
        self._validation_error_msg = None
        try:
            result = self._validate()
            if result:
                result = self._validate_tx_size()
            assert result == (self._validation_error_msg is None)

            return result
        except Exception as e:
            self._validation_error_msg = str(e)
            return False

    def complete_init(self) -> None:
        assert self.is_valid()

        for stage in self._prep_stage_list:
            stage.complete_init()

    def prep_before_emulate(self) -> bool:
        assert self.is_valid()

        # recheck already sent transactions
        tx_name_list: List[str] = list()
        for stage in self._prep_stage_list:
            tx_name_list.extend(stage.get_tx_name_list())
        self._recheck_tx_list(tx_name_list)

        # generate the new transaction
        return self._send_tx_list(self._build_prep_tx_list())

    def update_after_emulate(self) -> None:
        assert self.is_valid()

        for stage in self._prep_stage_list:
            stage.update_after_emulate()

    def has_good_sol_tx_receipt(self) -> bool:
        return self._sol_tx_list_sender.has_good_sol_tx_receipt()

    @abc.abstractmethod
    def execute(self) -> NeonTxResultInfo:
        pass

    @abc.abstractmethod
    def cancel(self) -> None:
        pass

    def _validate_tx_size(self) -> bool:
        self._build_tx().validate(self._ctx.signer)  # <- there will be exception
        return True

    def _validate_tx_has_chainid(self) -> bool:
        if self._ctx.neon_tx_info.has_chain_id():
            return True

        self._validation_error_msg = 'Transaction without chain-id'
        return False

    def _validate_stuck_tx(self) -> bool:
        if not self._ctx.is_stuck_tx():
            return True

        self._validation_error_msg = 'Stuck transaction'
        return False

    def _build_prep_tx_list(self) -> Generator[List[SolTx], None, None]:
        tx_list_list: List[List[SolTx]] = list()

        for stage in self._prep_stage_list:
            new_tx_list_list = stage.build_tx_list()

            while len(new_tx_list_list) > len(tx_list_list):
                tx_list_list.append(list())
            for tx_list, new_tx_list in zip(tx_list_list, new_tx_list_list):
                tx_list.extend(new_tx_list)

        yield from tx_list_list

    def _recheck_tx_list(self, tx_name_list: List[str]) -> bool:
        tx_list = self._ctx.pop_sol_tx_list(tx_name_list)
        if len(tx_list) == 0:
            return False

        tx_list_sender = self._sol_tx_list_sender
        tx_list_sender.clear()
        try:
            return tx_list_sender.recheck(tx_list)
        finally:
            self._store_sol_tx_list()

    def _send_tx_list(self, tx_list_generator: Generator[List[SolTx], None, None]) -> bool:
        tx_list_sender = self._sol_tx_list_sender
        tx_list_sender.clear()
        try:
            has_tx_list = False
            if tx_list_generator:
                for tx_list in tx_list_generator:
                    if len(tx_list) == 0:
                        continue

                    has_tx_list = True
                    tx_list_sender.send(tx_list)
            return has_tx_list
        finally:
            self._store_sol_tx_list()

    def _store_sol_tx_list(self):
        tx_list_sender = self._sol_tx_list_sender
        self._ctx.add_sol_tx_list([tx_state.tx for tx_state in tx_list_sender.tx_state_list])

    @cached_property
    def _sol_tx_list_sender(self) -> SolTxListSender:
        return SolTxListSender(self._ctx.config, self._ctx.solana, self._ctx.signer)

    def _build_cu_tx(self, ix: SolTxIx, name: str = '') -> SolLegacyTx:
        if len(name) == 0:
            name = self.name

        return SolLegacyTx(
            name=name,
            ix_list=[
                self._ctx.ix_builder.make_compute_budget_heap_ix(),
                self._ctx.ix_builder.make_compute_budget_cu_ix(),
                ix
            ]
        )

    @staticmethod
    def _find_sol_neon_ix(tx_send_state: SolTxSendState) -> Optional[SolNeonIxReceiptInfo]:
        block_slot = tx_send_state.receipt['slot']
        sol_neon_tx = SolNeonTxReceiptInfo.from_tx_receipt(block_slot, tx_send_state.receipt)
        for sol_neon_ix in sol_neon_tx.iter_sol_neon_ix():
            return sol_neon_ix
        return None

    @abc.abstractmethod
    def _build_tx(self) -> SolLegacyTx:
        pass

    @abc.abstractmethod
    def _validate(self) -> bool:
        pass
