from __future__ import annotations

import abc
import math
import time
import copy

from logged_groups import logged_group
from typing import Dict, Optional, List, Any, cast

from solana.transaction import Transaction
from solana.blockhash import Blockhash
from solana.account import Account as SolanaAccount

from ..common_neon.compute_budget import TransactionWithComputeBudget
from ..common_neon.emulator_interactor import call_trx_emulated
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.errors import BlockedAccountsError, NodeBehindError, SolanaUnavailableError, NonceTooLowError
from ..common_neon.solana_tx_list_sender import SolTxListInfo, SolTxListSender
from ..common_neon.solana_receipt_parser import SolTxError, SolReceiptParser
from ..common_neon.solana_neon_tx_receipt import SolTxMetaInfo, SolTxReceiptInfo
from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.utils import NeonTxResultInfo
from ..common_neon.data import NeonEmulatedResult
from ..common_neon.environment_data import RETRY_ON_FAIL, EVM_STEP_COUNT
from ..common_neon.elf_params import ElfParams
from ..common_neon.evm_log_decoder import decode_neon_tx_result
from ..common_neon.address import EthereumAddress

from ..common_neon.solana_alt import AddressLookupTableInfo
from ..common_neon.solana_alt_builder import AddressLookupTableTxBuilder, AddressLookupTableTxSet
from ..common_neon.solana_alt_close_queue import AddressLookupTableCloseQueue
from ..common_neon.solana_v0_transaction import V0Transaction

from .transaction_sender_ctx import AccountTxListBuilder, NeonTxSendCtx


@logged_group("neon.MemPool")
class BaseNeonTxStrategy(abc.ABC):
    NAME = 'UNKNOWN STRATEGY'

    def __init__(self, ctx: NeonTxSendCtx):
        self._validation_error_msg: Optional[str] = None
        self._ctx = ctx
        self._iter_evm_step_cnt = EVM_STEP_COUNT

    @property
    def _account_tx_list_builder(self) -> AccountTxListBuilder:
        return self._ctx.account_tx_list_builder

    @property
    def _alt_close_queue(self) -> AddressLookupTableCloseQueue:
        return self._ctx.alt_close_queue

    @property
    def _builder(self) -> NeonIxBuilder:
        return self._ctx.builder

    @property
    def _solana(self) -> SolanaInteractor:
        return self._ctx.solana

    @property
    def _signer(self) -> SolanaAccount:
        return self._ctx.resource.signer

    @property
    def _neon_tx(self) -> NeonTx:
        return self._ctx.neon_tx

    @property
    def neon_sig(self) -> str:
        return self._ctx.neon_sig

    @property
    def validation_error_msg(self) -> str:
        assert not self.is_valid()
        return cast(str, self._validation_error_msg)

    def is_valid(self) -> bool:
        return self._validation_error_msg is None

    @abc.abstractmethod
    def validate(self) -> bool:
        self._validation_error_msg = 'Not implemented'
        return False

    def _validate_notdeploy_tx(self) -> bool:
        if len(self._ctx.neon_tx.toAddress) == 0:
            self._validation_error_msg = 'Deploy transaction'
            return False
        return True

    def _validate_tx_size(self) -> bool:
        tx = self.build_tx(1)
        # Predefined blockhash is used only to check transaction size, the transaction won't be sent to network
        tx.recent_blockhash = Blockhash('4NCYB3kRT8sCNodPNuCZo8VUh4xqpBQxsxed2wd9xaD4')
        tx.sign(self._signer)
        try:
            tx.serialize()
            return True
        except Exception as err:
            if SolReceiptParser(err).check_if_big_transaction():
                self._validation_error_msg = 'Too big transaction size'
                return False
            self._validation_error_msg = str(err)
            raise

    def _validate_tx_has_chainid(self) -> bool:
        if self._neon_tx.hasChainId():
            return True

        self._validation_error_msg = "Transaction without chain-id"
        return False

    @abc.abstractmethod
    def decrease_iter_evm_step_cnt(self, tx_list: List[Transaction]) -> List[Transaction]:
        pass

    def _execute_prep_tx_list(self, tx_list_info_list: List[SolTxListInfo]) -> None:
        assert self.is_valid()
        tx_sender = SolTxListSender(self._solana, self._signer)
        for tx_list_info in tx_list_info_list:
            tx_sender.send(tx_list_info)

    def _build_prep_tx_list_before_emulate(self) -> List[SolTxListInfo]:
        assert self.is_valid()
        return []

    def prep_before_emulate(self) -> bool:
        assert self.is_valid()
        tx_list_info_list = self._build_prep_tx_list_before_emulate()
        if len(tx_list_info_list) == 0:
            return False
        self._execute_prep_tx_list(tx_list_info_list)
        return True

    def _build_prep_tx_list_after_emulate(self) -> List[SolTxListInfo]:
        assert self.is_valid()
        tx_list_info = self._account_tx_list_builder.get_tx_list_info()

        alt_tx_list = self._alt_close_queue.pop_tx_list(self._signer.public_key())
        if len(alt_tx_list):
            tx_list_info.tx_list.extend(alt_tx_list)
            tx_list_info.name_list.extend(['CloseLookupTable' for _ in alt_tx_list])

        if len(tx_list_info.tx_list) == 0:
            return []
        return [tx_list_info]

    def prep_after_emulate(self) -> bool:
        assert self.is_valid()
        tx_list_info_list = self._build_prep_tx_list_after_emulate()
        if len(tx_list_info_list) == 0:
            return False
        self._execute_prep_tx_list(tx_list_info_list)
        self._account_tx_list_builder.clear_tx_list()
        return True

    @abc.abstractmethod
    def build_tx(self, idx=0) -> Transaction:
        return TransactionWithComputeBudget()

    def build_cancel_tx(self) -> Transaction:
        return TransactionWithComputeBudget().add(self._builder.make_cancel_instruction())

    def _build_tx_list(self, cnt: int) -> SolTxListInfo:
        return SolTxListInfo(
            tx_list=[self.build_tx(i) for i in range(cnt)],
            name_list=[self.NAME for _ in range(cnt)]
        )

    @abc.abstractmethod
    def execute(self) -> NeonTxResultInfo:
        assert self.is_valid()
        return NeonTxResultInfo()


@logged_group("neon.MemPool")
class SimpleNeonTxSender(SolTxListSender):
    def __init__(self, strategy: BaseNeonTxStrategy, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._strategy = strategy
        self.neon_tx_res = NeonTxResultInfo()

    def _decode_neon_tx_result(self, sol_receipt: Dict[str, Any]) -> None:
        if self.neon_tx_res.is_valid():
            return

        block_slot = sol_receipt['slot']
        sol_sig = sol_receipt['transaction']['signatures'][0]
        sol_tx = SolTxReceiptInfo(SolTxMetaInfo(block_slot, sol_sig, sol_receipt))
        for sol_neon_ix in sol_tx.iter_sol_neon_ix():
            if decode_neon_tx_result(sol_neon_ix.iter_log(), self._strategy.neon_sig, self.neon_tx_res):
                break

    def _on_success_send(self, sol_tx: Transaction, sol_receipt: Dict[str, Any]) -> None:
        self._decode_neon_tx_result(sol_receipt)
        super()._on_success_send(sol_tx, sol_receipt)

    def _on_post_send(self) -> None:
        if self.neon_tx_res.is_valid():
            self.debug(f'Got Neon tx result: {self.neon_tx_res}')
            self.clear()
        else:
            super()._on_post_send()
            if not len(self._tx_list):
                raise RuntimeError('Run out of attempts to execute transaction')


@logged_group("neon.MemPool")
class SimpleNeonTxStrategy(BaseNeonTxStrategy):
    NAME = 'CallFromRawEthereumTX'
    IS_SIMPLE = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def decrease_iter_evm_step_cnt(self, tx_list: List[Transaction]) -> List[Transaction]:
        raise NotImplementedError(f"{self.NAME} strategy doesn't know anything about iterations")

    def validate(self) -> bool:
        self._validation_error_msg = None
        return (
            self._validate_evm_step_cnt() and
            self._validate_notdeploy_tx() and
            self._validate_tx_has_chainid() and
            self._validate_tx_size()
        )

    def _validate_evm_step_cnt(self) -> bool:
        if self._ctx.emulated_evm_step_cnt > self._iter_evm_step_cnt:
            self._validation_error_msg = 'Too big number of EVM steps'
            return False
        return True

    def build_tx(self, _=0) -> Transaction:
        tx = TransactionWithComputeBudget()
        tx.add(self._builder.make_noniterative_call_transaction(len(tx.instructions)))
        return tx

    def execute(self) -> NeonTxResultInfo:
        assert self.is_valid()
        tx_list_info = SolTxListInfo([self.NAME], [self.build_tx()])

        tx_sender = SimpleNeonTxSender(self, self._solana, self._signer)
        tx_sender.send(tx_list_info)
        if not tx_sender.neon_tx_res.is_valid():
            raise tx_sender.raise_budget_exceeded()
        return tx_sender.neon_tx_res


@logged_group("neon.MemPool")
class IterativeNeonTxSender(SimpleNeonTxSender):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_canceled = False
        self._postponed_exception: Optional[Exception] = None

    def _cancel(self) -> None:
        self.debug(f'Cancel the transaction')
        self.clear()
        self._name = 'CancelWithNonce'
        self._is_canceled = True
        self._retry_idx = 0  # force the cancel sending
        self._tx_list = [self._strategy.build_cancel_tx()]

    def _decrease_iter_evm_step_cnt(self) -> None:
        tx_list = self._strategy.decrease_iter_evm_step_cnt(self._get_full_tx_list())
        if not len(tx_list):
            return self._cancel()
        self.clear()
        self._tx_list = tx_list

    def _on_success_send(self, sol_tx: Transaction, sol_receipt: {}) -> None:
        if self._is_canceled:
            # Transaction with cancel is confirmed
            self.neon_tx_res.fill_result(status="0x0", gas_used='0x0', return_value='')
        else:
            super()._on_success_send(sol_tx, sol_receipt)

    def _set_postponed_exception(self, exception: Exception) -> None:
        if not self._postponed_exception:
            self._postponed_exception = exception

    def _raise_error(self) -> None:
        assert self._postponed_exception is not None
        raise self._postponed_exception

    def _on_post_send(self) -> None:
        # Result is received
        if self.neon_tx_res.is_valid():
            self.debug(f'Got Neon tx {"cancel" if self._is_canceled else "result"}: {self.neon_tx_res}')
            if self._is_canceled and self._postponed_exception:
                self._raise_error()
            return self.clear()

        if len(self._node_behind_list):
            self.warning(f'Node is behind by {self._slots_behind} slots')
            raise NodeBehindError()

        # Unknown error happens - cancel the transaction
        if self._unknown_error_receipt is not None:
            self._set_postponed_exception(SolTxError(self._unknown_error_receipt))
            if self._is_canceled:
                self._raise_error()

            self._unknown_error_list.clear()
            self._unknown_error_receipt = None
            if len(self.success_sig_list):
                return self._cancel()
            self._raise_error()

        # There is no more retries to send transactions
        if self._retry_idx >= RETRY_ON_FAIL:
            self._set_postponed_exception(RuntimeError('No more retries to complete transaction!'))
            if (not self._is_canceled) and len(self.success_sig_list):
                return self._cancel()
            self._raise_error()

        # Blockhash is changed (((
        if len(self._bad_block_list):
            self._blockhash = None

        # Address Lookup Tables can't be used in the same block with extending of it
        if len(self._alt_invalid_index_list):
            time.sleep(self.ONE_BLOCK_TIME)
        # Accounts are blocked, so try to lock them
        elif len(self._blocked_account_list):
            raise BlockedAccountsError()

        # Compute budged is exceeded, so decrease EVM steps per iteration
        if len(self._budget_exceeded_list):
            return self._decrease_iter_evm_step_cnt()

        self._move_tx_list()

        # if no iterations and no result then add the additional iteration
        if not len(self._tx_list):
            self.debug('No result -> add the additional iteration')
            self._tx_list.append(self._strategy.build_tx())


@logged_group("neon.MemPool")
class IterativeNeonTxStrategy(BaseNeonTxStrategy):
    NAME = 'PartialCallOrContinueFromRawEthereumTX'
    IS_SIMPLE = False

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._compute_unit_cnt: Optional[int] = None

    def validate(self) -> bool:
        self._validation_error_msg = None
        return (
            self._validate_notdeploy_tx() and
            self._validate_tx_size() and
            self._validate_evm_step_cnt() and
            self._validate_tx_has_chainid()
        )

    def _validate_evm_step_cnt(self) -> bool:
        # Only the instruction with a holder account allows to pass a unique number to make the transaction unique
        emulated_evm_step_cnt = self._ctx.emulated_evm_step_cnt
        max_evm_step_cnt = self._iter_evm_step_cnt * 25
        if emulated_evm_step_cnt > max_evm_step_cnt:
            self._validation_error_msg = 'Big number of EVM steps'
            return False
        return True

    def decrease_iter_evm_step_cnt(self, tx_list: List[Transaction]) -> List[Transaction]:
        if self._iter_evm_step_cnt <= 10:
            return []

        prev_total_iteration_cnt = len(tx_list)
        evm_step_cnt = self._iter_evm_step_cnt
        prev_evm_step_cnt = evm_step_cnt
        total_evm_step_cnt = prev_total_iteration_cnt * evm_step_cnt

        if evm_step_cnt > 170:
            evm_step_cnt -= 150
        else:
            self._compute_unit_cnt = 1_375_000
            evm_step_cnt = 10
        self._iter_evm_step_cnt = evm_step_cnt
        total_iteration_cnt = math.ceil(total_evm_step_cnt / evm_step_cnt)

        self.debug(
            f'Decrease EVM steps from {prev_evm_step_cnt} to {evm_step_cnt}, ' +
            f'iterations increase from {prev_total_iteration_cnt} to {total_iteration_cnt}'
        )

        return [self.build_tx(idx) for idx in range(total_iteration_cnt)]

    def build_tx(self, idx=0) -> Transaction:
        tx = TransactionWithComputeBudget(compute_units=self._compute_unit_cnt)
        # generate unique tx
        evm_step_cnt = self._iter_evm_step_cnt + idx
        tx.add(self._builder.make_partial_call_or_continue_transaction(evm_step_cnt, len(tx.instructions)))
        return tx

    def _calc_iter_cnt(self) -> int:
        iter_cnt = math.ceil(self._ctx.emulated_evm_step_cnt / self._iter_evm_step_cnt)
        iter_cnt = math.ceil(self._ctx.emulated_evm_step_cnt / (self._iter_evm_step_cnt - iter_cnt))
        return iter_cnt

    def execute(self) -> NeonTxResultInfo:
        assert self.is_valid()
        emulated_evm_step_cnt = self._ctx.emulated_evm_step_cnt
        iter_cnt = self._calc_iter_cnt()
        self.debug(f'Total iterations {iter_cnt} for {emulated_evm_step_cnt} ({self._iter_evm_step_cnt}) EVM steps')

        tx_list_info = self._build_tx_list(iter_cnt)
        tx_sender = IterativeNeonTxSender(self, self._solana, self._signer)
        tx_sender.send(tx_list_info)
        return tx_sender.neon_tx_res


@logged_group("neon.MemPool")
class HolderNeonTxStrategy(IterativeNeonTxStrategy):
    NAME = 'ExecuteTrxFromAccountDataIterativeOrContinue'

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def validate(self) -> bool:
        self._validation_error_msg = None
        return (
            self._validate_tx_size() and
            self._validate_tx_has_chainid()
        )

    def build_tx(self, idx=0) -> Transaction:
        evm_step_cnt = self._iter_evm_step_cnt
        return TransactionWithComputeBudget(compute_units=self._compute_unit_cnt).add(
            self._builder.make_partial_call_or_continue_from_account_data_instruction(evm_step_cnt, idx)
        )

    def _calc_iter_cnt(self) -> int:
        return math.ceil(self._ctx.emulated_evm_step_cnt / self._iter_evm_step_cnt) + 1

    def _build_prep_tx_list_before_emulate(self) -> List[SolTxListInfo]:
        assert self.is_valid()

        if self._ctx.is_holder_completed:
            return []

        # write eth transaction to the holder account
        tx_list_info = SolTxListInfo([], [])
        holder_msg_offset = 0
        holder_msg = copy.copy(self._builder.holder_msg)
        holder_msg_size = ElfParams().holder_msg_size
        while len(holder_msg):
            (holder_msg_part, holder_msg) = (holder_msg[:holder_msg_size], holder_msg[holder_msg_size:])
            tx = TransactionWithComputeBudget().add(
                self._builder.make_write_instruction(holder_msg_offset, holder_msg_part)
            )
            tx_list_info.name_list.append('WriteWithHolder')
            tx_list_info.tx_list.append(tx)
            holder_msg_offset += holder_msg_size

        self._ctx.set_holder_completed()
        return [tx_list_info]


@logged_group("neon.MemPool")
class AltHolderNeonTxStrategy(HolderNeonTxStrategy):
    NAME = 'AltExecuteTrxFromAccountDataIterativeOrContinue'

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._alt_builder: Optional[AddressLookupTableTxBuilder] = None
        self._alt_info: Optional[AddressLookupTableInfo] = None
        self._alt_tx_set: Optional[AddressLookupTableTxSet] = None

    def validate(self) -> bool:
        self._validation_error_msg = None
        return (
            self._validate_tx_has_chainid() and
            self._init_alt_info() and
            self._validate_tx_size()
        )

    def _build_legacy_tx(self, idx=0) -> Transaction:
        return super().build_tx(idx)

    def _build_legacy_cancel_tx(self) -> Transaction:
        return super().build_cancel_tx()

    def _init_alt_info(self) -> bool:
        # TODO: if there are a lot of changes in the account list, the alt should be regenerated
        if self._alt_info is not None:
            return True

        legacy_tx = self._build_legacy_tx()
        try:
            alt_builder = AddressLookupTableTxBuilder(self._solana, self._builder, self._signer, self._alt_close_queue)
            self._alt_info = alt_builder.build_alt_info(legacy_tx)
            self._alt_builder = alt_builder
        except Exception as e:
            self._validation_error_msg = str(e)
            return False
        return True

    def build_tx(self, idx=0) -> Transaction:
        legacy_tx = self._build_legacy_tx(idx)
        return V0Transaction(address_table_lookups=[self._alt_info]).add(legacy_tx)

    def build_cancel_tx(self) -> Transaction:
        legacy_tx = self._build_legacy_cancel_tx()
        return V0Transaction(address_table_lookups=[self._alt_info]).add(legacy_tx)

    def _build_prep_tx_list_before_emulate(self) -> List[SolTxListInfo]:
        assert self.is_valid()
        tx_list_info_list = super()._build_prep_tx_list_before_emulate()

        self._alt_tx_set = self._alt_builder.build_alt_tx_set(self._alt_info)
        alt_tx_list_info_list = self._alt_builder.build_prep_alt_list(self._alt_tx_set)

        if len(tx_list_info_list) > 0:
            tx_list_info_list[-1].extend(alt_tx_list_info_list[0])
            alt_tx_list_info_list = alt_tx_list_info_list[1:]
        if len(alt_tx_list_info_list) > 0:
            tx_list_info_list.extend(alt_tx_list_info_list)

        return tx_list_info_list

    def prep_before_emulate(self) -> bool:
        result = super().prep_before_emulate()
        self._alt_builder.update_alt_info_list([self._alt_info])
        return result

    def _post_execute(self) -> None:
        if (self._alt_tx_set is None) or (len(self._alt_tx_set) == 0):
            return

        try:
            tx_list_info_list = self._alt_builder.build_done_alt_tx_set(self._alt_tx_set)
            self._execute_prep_tx_list(tx_list_info_list)
        except (Exception,):
            # TODO: Move this skip into solana receipt checker
            pass

    def execute(self) -> NeonTxResultInfo:
        try:
            return super().execute()
        finally:
            self._post_execute()


class BaseNoChainIdNeonStrategy:
    @staticmethod
    def _validate_tx_wo_chainid(self) -> bool:
        return not self._neon_tx.hasChainId()

    @staticmethod
    def _build_tx_wo_chainid(self, idx: int) -> Transaction:
        return TransactionWithComputeBudget(compute_units=self._compute_unit_cnt).add(
            self._builder.make_partial_call_or_continue_from_account_data_no_chainid_instruction(
                self._iter_evm_step_cnt, idx
            )
        )


@logged_group("neon.MemPool")
class NoChainIdNeonTxStrategy(HolderNeonTxStrategy, BaseNoChainIdNeonStrategy):
    NAME = 'ExecuteTrxFromAccountDataIterativeOrContinueNoChainId'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self) -> bool:
        self._validation_error_msg = None
        if not self._validate_tx_wo_chainid(self):
            self._validation_error_msg = 'Normal transaction'
            return False

        return self._validate_tx_size()

    def build_tx(self, idx=0) -> Transaction:
        return self._build_tx_wo_chainid(self, idx)


@logged_group("neon.MemPool")
class AltNoChainIdNeonTxStrategy(AltHolderNeonTxStrategy, BaseNoChainIdNeonStrategy):
    NAME = 'AltExecuteTrxFromAccountDataIterativeOrContinueNoChainId'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self) -> bool:
        self._validation_error_msg = None
        if not self._validate_tx_wo_chainid(self):
            self._validation_error_msg = 'Normal transaction'
            return False

        return self._validate_tx_size()

    def _build_legacy_tx(self, idx=0) -> Transaction:
        return self._build_tx_wo_chainid(self, idx)


@logged_group("neon.MemPool")
class NeonTxSendStrategyExecutor:
    STRATEGY_LIST = [
        SimpleNeonTxStrategy,
        IterativeNeonTxStrategy, HolderNeonTxStrategy, AltHolderNeonTxStrategy,
        NoChainIdNeonTxStrategy, AltNoChainIdNeonTxStrategy
    ]

    def __init__(self, ctx: NeonTxSendCtx):
        super().__init__()
        self._ctx = ctx
        self._operator = f'{str(self._ctx.resource)}'

    def execute(self) -> NeonTxResultInfo:
        self._validate_nonce()
        self._ctx.init()
        return self._execute()

    def _get_state_tx_cnt(self) -> int:
        neon_account_info = self._ctx.solana.get_neon_account_info(EthereumAddress(self._ctx.sender))
        return neon_account_info.tx_count if neon_account_info is not None else 0

    def _emulate_neon_tx(self) -> None:
        emulated_result: NeonEmulatedResult = call_trx_emulated(self._ctx.neon_tx)
        self._ctx.neon_tx_exec_cfg.set_emulated_result(emulated_result)
        self._validate_nonce()
        self._ctx.init()

    def _validate_nonce(self) -> None:
        state_tx_cnt = self._get_state_tx_cnt()
        self._ctx.neon_tx_exec_cfg.set_state_tx_cnt(state_tx_cnt)
        if self._ctx.state_tx_cnt > self._ctx.neon_tx.nonce:
            raise NonceTooLowError()

    def _execute(self) -> NeonTxResultInfo:
        for Strategy in self.STRATEGY_LIST:
            try:
                strategy: BaseNeonTxStrategy = Strategy(self._ctx)
                if not strategy.validate():
                    self.debug(f'Skip strategy {Strategy.NAME}: {strategy.validation_error_msg}')
                    continue
                self.debug(f'Use strategy {Strategy.NAME}')

                strategy.prep_before_emulate()
                for i in range(RETRY_ON_FAIL):
                    self._emulate_neon_tx()

                    if not strategy.validate():
                        self.debug(f'Skip strategy {Strategy.NAME}: {strategy.validation_error_msg}')
                        continue

                    if strategy.prep_after_emulate():
                        continue
                    return strategy.execute()
                raise RuntimeError('fail to sync the emulation and the execution')

            except (BlockedAccountsError, NodeBehindError, SolanaUnavailableError, NonceTooLowError):
                raise
            except Exception as e:
                if (not Strategy.IS_SIMPLE) or (not SolReceiptParser(e).check_if_budget_exceeded()):
                    raise
        raise RuntimeError('transaction is too big for execution')
