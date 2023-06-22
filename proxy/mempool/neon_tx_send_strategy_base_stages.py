import copy
import logging

from typing import List, Optional, Dict, Union

from ..common_neon.constants import EMPTY_HOLDER_TAG, ACTIVE_HOLDER_TAG, FINALIZED_HOLDER_TAG, HOLDER_TAG
from ..common_neon.elf_params import ElfParams
from ..common_neon.errors import BadResourceError, HolderContentError, ALTContentError, StuckTxError
from ..common_neon.solana_alt import ALTInfo
from ..common_neon.solana_alt_limit import ALTLimit
from ..common_neon.solana_alt_builder import ALTTxBuilder, ALTTxSet
from ..common_neon.solana_tx import SolTx, SolTxSizeError
from ..common_neon.solana_tx_legacy import SolLegacyTx
from ..common_neon.solana_tx_v0 import SolV0Tx
from ..common_neon.layouts import HolderAccountInfo
from ..common_neon.data import NeonEmulatedResult

from ..mempool.neon_tx_send_base_strategy import BaseNeonTxPrepStage
from ..mempool.neon_tx_sender_ctx import NeonTxSendCtx


LOG = logging.getLogger(__name__)


class WriteHolderNeonTxPrepStage(BaseNeonTxPrepStage):
    name = 'WriteHolderAccount'

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._holder_tag = EMPTY_HOLDER_TAG

    @property
    def holder_tag(self) -> int:
        return self._holder_tag

    def complete_init(self) -> None:
        if not self._ctx.is_stuck_tx():
            self._ctx.mark_resource_use()

    def _validate_holder_account(self) -> None:
        holder_info = self._get_holder_account_info()
        holder_acct = holder_info.holder_account
        self._holder_tag = holder_info.tag

        if holder_info.tag == FINALIZED_HOLDER_TAG:
            if not self._ctx.has_sol_tx(self.name):
                return
            elif holder_info.neon_tx_sig != self._ctx.neon_tx_info.sig:
                HolderContentError(str(holder_acct))

        elif holder_info.tag == ACTIVE_HOLDER_TAG:
            if holder_info.neon_tx_sig != self._ctx.neon_tx_info.sig:
                raise StuckTxError(holder_info.neon_tx_sig, str(holder_acct))

        elif holder_info.tag == HOLDER_TAG:
            if not self._ctx.has_sol_tx(self.name):
                return

            builder = self._ctx.ix_builder
            holder_msg_len = len(builder.holder_msg)
            if builder.holder_msg != holder_info.neon_tx_data[:holder_msg_len]:
                HolderContentError(str(holder_acct))

    def validate_stuck_tx(self) -> None:
        holder_info = self._get_holder_account_info()
        holder_acct = holder_info.holder_account
        self._holder_tag = holder_info.tag

        if holder_info.tag == FINALIZED_HOLDER_TAG:
            pass

        elif holder_info.tag == ACTIVE_HOLDER_TAG:
            if holder_info.neon_tx_sig != self._ctx.neon_tx_info.sig:
                self._holder_tag = FINALIZED_HOLDER_TAG
                LOG.debug(f'NeonTx in {str(holder_acct)} was finished...')
            else:
                self._read_blocked_account_list(holder_info)

        elif holder_info.tag == HOLDER_TAG:
            self._holder_tag = FINALIZED_HOLDER_TAG
            LOG.debug(f'NeonTx in {str(holder_acct)} was finished...')

    def _read_blocked_account_list(self, holder_info: HolderAccountInfo) -> None:
        acct_list: List[Dict[str, Union[bool, str]]] = list()
        for acct in holder_info.account_list:
            acct_list.append(dict(
                pubkey=acct.pubkey,
                is_writable=acct.is_writable
            ))

        emulated_result: NeonEmulatedResult = dict(
            accounts=list(),
            solana_accounts=acct_list,
            steps_executed=1
        )

        self._ctx.set_emulated_result(emulated_result)

    def _get_holder_account_info(self) -> HolderAccountInfo:
        holder_account = self._ctx.holder_account

        holder_info = self._ctx.solana.get_holder_account_info(holder_account)
        if holder_info is None:
            raise BadResourceError(f'Bad holder account {str(holder_account)}')
        elif holder_info.tag not in {FINALIZED_HOLDER_TAG, ACTIVE_HOLDER_TAG, HOLDER_TAG}:
            raise BadResourceError(f'Holder account {str(holder_account)} has bad tag: {holder_info.tag}')

        self._holder_tag = holder_info.tag
        return holder_info

    def get_tx_name_list(self) -> List[str]:
        if self._ctx.is_stuck_tx():
            return list()
        return [self.name]

    def build_tx_list(self) -> List[List[SolTx]]:
        if self._ctx.is_stuck_tx() or self._ctx.has_sol_tx(self.name):
            return list()

        builder = self._ctx.ix_builder

        tx_list: List[SolTx] = list()
        holder_msg_offset = 0
        holder_msg = copy.copy(builder.holder_msg)

        holder_msg_size = ElfParams().holder_msg_size
        while len(holder_msg):
            (holder_msg_part, holder_msg) = (holder_msg[:holder_msg_size], holder_msg[holder_msg_size:])
            tx = SolLegacyTx(
                name='WriteHolderAccount',
                ix_list=[builder.make_write_ix(holder_msg_offset, holder_msg_part)]
            )
            tx_list.append(tx)
            holder_msg_offset += holder_msg_size

        return [tx_list]

    def update_holder_tag(self) -> None:
        if self._ctx.is_stuck_tx():
            self.validate_stuck_tx()
        else:
            self._validate_holder_account()

    def update_after_emulate(self) -> None:
        self.update_holder_tag()


class ALTNeonTxPrepStage(BaseNeonTxPrepStage):
    def __init__(self, ctx: NeonTxSendCtx):
        super().__init__(ctx)
        self._test_legacy_tx: Optional[SolLegacyTx] = None
        self._actual_alt_info: Optional[ALTInfo] = None
        self._alt_info_dict: Dict[str, ALTInfo] = dict()
        self._alt_builder = ALTTxBuilder(self._ctx.solana, self._ctx.ix_builder, self._ctx.signer)
        self._alt_tx_set = ALTTxSet()

    @property
    def _alt_info_list(self) -> List[ALTInfo]:
        return list(self._alt_info_dict.values())

    def complete_init(self) -> None:
        self._ctx.mark_resource_use()  # using of the operator key for ALTs

    def _tx_has_valid_size(self, legacy_tx: SolLegacyTx) -> bool:
        try:
            self.build_tx(legacy_tx).validate(self._ctx.signer)
            return True
        except SolTxSizeError:
            return False

    def init_alt_info(self, legacy_tx: SolLegacyTx) -> bool:
        self._alt_info_dict.clear()
        self._test_legacy_tx = legacy_tx
        actual_alt_info = self._alt_builder.build_alt_info(legacy_tx)

        alt_info_list = self._filter_alt_info_list(actual_alt_info)
        if (len(self._alt_info_dict) > 0) and self._tx_has_valid_size(legacy_tx):
            return True

        actual_alt_info = self._extend_alt_info(actual_alt_info, alt_info_list)

        self._alt_tx_set = self._alt_builder.build_alt_tx_set(actual_alt_info)
        self._actual_alt_info = actual_alt_info
        self._add_alt_info(actual_alt_info)
        return True

    def _filter_alt_info_list(self, actual_alt_info: ALTInfo) -> List[ALTInfo]:
        alt_info_list: List[ALTInfo] = list()
        for alt_address in self._ctx.alt_address_list:
            alt_info = ALTInfo(alt_address)
            try:
                self._alt_builder.update_alt_info_list([alt_info])
                alt_info_list.append(alt_info)

                if actual_alt_info.remove_account_key_list(alt_info.account_key_list):
                    self._add_alt_info(alt_info)

            except Exception as e:
                LOG.debug(f'Skip ALT {alt_address.table_account}: {str(e)}')

        return alt_info_list

    def _add_alt_info(self, alt_info: ALTInfo) -> None:
        table_account = alt_info.alt_address.table_account
        if table_account in self._alt_info_dict:
            return

        self._alt_info_dict[table_account] = alt_info
        if alt_info.is_exist():
            LOG.debug(f'Use existing ALT: {alt_info.alt_address.table_account}')
        else:
            LOG.debug(f'Use new ALT: {alt_info.alt_address.table_account}')

    def _extend_alt_info(self, actual_alt_info: ALTInfo, alt_info_list: List[ALTInfo]) -> ALTInfo:
        if self._ctx.is_stuck_tx():
            return actual_alt_info

        for alt_info in alt_info_list:
            if actual_alt_info.len_account_key_list + alt_info.len_account_key_list >= ALTLimit.max_alt_account_cnt:
                continue

            alt_info.add_account_key_list(actual_alt_info.account_key_list)
            return alt_info

        return actual_alt_info

    def get_tx_name_list(self) -> List[str]:
        return self._alt_builder.get_tx_name_list()

    def build_tx_list(self) -> List[List[SolTx]]:
        if len(self._alt_tx_set) == 0:
            return list()

        if self._actual_alt_info is not None:
            self._ctx.add_alt_address(self._actual_alt_info.alt_address)
            self._actual_alt_info = None

        return self._alt_builder.build_prep_alt_list(self._alt_tx_set)

    def update_after_emulate(self) -> None:
        alt_info = self._actual_alt_info
        legacy_tx = self._test_legacy_tx

        self._alt_tx_set.clear()
        self._actual_alt_info = None
        self._test_legacy_tx = None

        self._alt_builder.update_alt_info_list(self._alt_info_list)
        if (legacy_tx is None) or (alt_info is None):
            pass
        elif not self._tx_has_valid_size(legacy_tx):
            raise ALTContentError(str(alt_info.alt_address), 'is not synced yet')

    def build_tx(self, legacy_tx: SolLegacyTx) -> SolV0Tx:
        return SolV0Tx(name=legacy_tx.name, ix_list=legacy_tx.ix_list, alt_info_list=self._alt_info_list)


def alt_strategy(cls):
    class ALTStrategy(cls):
        name = 'ALT+' + cls.name

        def __init__(self, ctx: NeonTxSendCtx):
            cls.__init__(self, ctx)
            self._alt_stage = ALTNeonTxPrepStage(ctx)
            self._prep_stage_list.append(self._alt_stage)

        def _validate(self) -> bool:
            return (
                self._validate_account_list_len() and
                self._alt_stage.init_alt_info(cls._build_tx(self)) and
                cls._validate(self)
            )

        def _validate_account_list_len(self) -> bool:
            len_account_list = self._ctx.len_account_list + 6
            if len_account_list < ALTLimit.max_tx_account_cnt:
                self._validation_error_msg = (
                    f'Number of accounts {len_account_list} less than {ALTLimit.max_tx_account_cnt}'
                )
                return False
            return True

        def _build_tx(self) -> SolV0Tx:
            return self._alt_stage.build_tx(cls._build_tx(self))

        def _build_cancel_tx(self) -> SolV0Tx:
            return self._alt_stage.build_tx(cls._build_cancel_tx(self))

    return ALTStrategy
