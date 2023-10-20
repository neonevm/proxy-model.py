import logging

from typing import List, Optional, Dict

from ..common_neon.errors import ALTContentError
from ..common_neon.solana_alt import ALTInfo
from ..common_neon.solana_alt_limit import ALTLimit
from ..common_neon.solana_alt_builder import ALTTxBuilder, ALTTxSet
from ..common_neon.solana_tx import SolTx, SolTxSizeError
from ..common_neon.solana_tx_legacy import SolLegacyTx
from ..common_neon.solana_tx_v0 import SolV0Tx

from .neon_tx_send_base_strategy import BaseNeonTxPrepStage
from .neon_tx_sender_ctx import NeonTxSendCtx


LOG = logging.getLogger(__name__)


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
