import abc

from logged_groups import logged_group
from typing import Optional, List, cast

from ..common_neon.solana_transaction import SolLegacyTx, SolTx, SolBlockhash
from ..common_neon.solana_tx_list_sender import SolTxListSender
from ..common_neon.elf_params import ElfParams
from ..common_neon.utils import NeonTxResultInfo

from ..mempool.neon_tx_sender_ctx import NeonTxSendCtx


@logged_group("neon.MemPool")
class BaseNeonTxPrepStage(abc.ABC):
    def __init__(self, ctx: NeonTxSendCtx):
        self._ctx = ctx

    @abc.abstractmethod
    def build_prep_tx_list_before_emulate(self) -> List[List[SolTx]]:
        pass

    @abc.abstractmethod
    def update_after_emulate(self) -> None:
        pass


@logged_group("neon.MemPool")
class BaseNeonTxStrategy(abc.ABC):
    name = 'UNKNOWN STRATEGY'

    def __init__(self, ctx: NeonTxSendCtx):
        self._bpf_cycle_cnt: Optional[int] = None
        self._validation_error_msg: Optional[str] = None
        self._prep_stage_list: List[BaseNeonTxPrepStage] = []
        self._ctx = ctx
        self._base_evm_step_cnt = ElfParams().neon_evm_steps
        self._start_evm_step_cnt = int(self._base_evm_step_cnt * (ctx.config.evm_step_cnt_inc_pct + 1))

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
            assert result != (self._validation_error_msg is not None)

            return result
        except Exception as e:
            self._validation_error_msg = str(e)
            return False

    def _validate_notdeploy_tx(self) -> bool:
        if len(self._ctx.neon_tx.toAddress) == 0:
            self._validation_error_msg = 'Deploy transaction'
            return False
        return True

    def _validate_tx_size(self) -> bool:
        tx = self._build_tx()

        # Predefined blockhash is used only to check transaction size, the transaction won't be sent to network
        tx.recent_blockhash = SolBlockhash('4NCYB3kRT8sCNodPNuCZo8VUh4xqpBQxsxed2wd9xaD4')
        tx.sign(self._ctx.signer)
        tx.serialize()  # <- there will be exception
        return True

    def _validate_tx_has_chainid(self) -> bool:
        if self._ctx.neon_tx.hasChainId():
            return True

        self._validation_error_msg = 'Transaction without chain-id'
        return False

    def prep_before_emulate(self) -> bool:
        assert self.is_valid()

        tx_list_list: List[List[SolTx]] = []
        for stage in self._prep_stage_list:
            new_tx_list_list = stage.build_prep_tx_list_before_emulate()

            while len(new_tx_list_list) > len(tx_list_list):
                tx_list_list.append([])
            for tx_list, new_tx_list in zip(tx_list_list, new_tx_list_list):
                tx_list.extend(new_tx_list)

        if len(tx_list_list) == 0:
            return False

        tx_sender = SolTxListSender(self._ctx.config, self._ctx.solana, self._ctx.signer)
        for tx_list in tx_list_list:
            tx_sender.send(tx_list)
        return True

    def update_after_emulate(self) -> None:
        assert self.is_valid()

        for stage in self._prep_stage_list:
            stage.update_after_emulate()

    def _build_cancel_tx(self) -> SolLegacyTx:
        return BaseNeonTxStrategy._build_tx(self).add(
            self._ctx.ix_builder.make_cancel_ix()
        )

    @abc.abstractmethod
    def _build_tx(self) -> SolLegacyTx:
        return SolLegacyTx().add(
            self._ctx.ix_builder.make_compute_budget_heap_ix(),
            self._ctx.ix_builder.make_compute_budget_cu_ix(self._bpf_cycle_cnt)
        )

    @abc.abstractmethod
    def _validate(self) -> bool:
        pass

    @abc.abstractmethod
    def execute(self) -> NeonTxResultInfo:
        pass
