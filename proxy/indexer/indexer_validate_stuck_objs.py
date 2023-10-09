from typing import List


from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.config import Config
from ..common_neon.solana_tx import SolPubKey

from ..neon_core_api.neon_client import NeonClient
from ..neon_core_api.neon_layouts import HolderStatus

from .indexed_objects import NeonIndexedBlockInfo, NeonIndexedHolderInfo, NeonIndexedTxInfo


class StuckObjectValidator:
    def __init__(self, config: Config, solana: SolInteractor):
        self._config = config
        self._solana = solana
        self._neon_client = NeonClient(config)
        self._last_slot = 0

    def validate_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        block_slot = neon_block.block_slot
        last_block_slot = block_slot - self._config.stuck_object_validate_blockout
        if last_block_slot < self._last_slot:
            return
        elif self._last_slot == 0:
            self._last_slot = block_slot
            return
        elif neon_block.stuck_block_slot > neon_block.block_slot:
            self._last_slot = block_slot
            return
        self._last_slot = block_slot

        neon_block.check_stuck_objs(self._config)
        failed_holder_list: List[NeonIndexedHolderInfo] = list()
        for holder in neon_block.iter_stuck_neon_holder():
            if holder.last_block_slot > last_block_slot:
                pass
            elif not self._is_valid_holder(holder.account, holder.neon_tx_sig):
                failed_holder_list.append(holder)

        failed_tx_list: List[NeonIndexedTxInfo] = list()
        for tx in neon_block.iter_stuck_neon_tx():
            if tx.last_block_slot > last_block_slot:
                continue
            elif not self._is_valid_holder(tx.holder_account, tx.neon_tx.sig):
                failed_tx_list.append(tx)

        neon_block.fail_neon_holder_list(failed_holder_list)
        neon_block.fail_neon_tx_list(failed_tx_list)

    def _is_valid_holder(self, holder_acct: str, neon_tx_sig: str) -> bool:
        holder_info = self._neon_client.get_holder_account_info(SolPubKey.from_string(holder_acct))
        if holder_info is None:
            return False

        if holder_info.neon_tx_sig == neon_tx_sig:
            return holder_info.status != HolderStatus.Finalized
        return False
