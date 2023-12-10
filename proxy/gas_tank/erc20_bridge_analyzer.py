import logging

from typing import Optional

from ..common_neon.address import NeonAddress

from .gas_tank_types import GasTankNeonTxAnalyzer, GasTankTxInfo


LOG = logging.getLogger(__name__)

# keccak256("Transfer(address,address,uint256)")
TRANSFER_EVENT = bytes.fromhex('ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef')


class ERC20Analyzer(GasTankNeonTxAnalyzer):
    name = 'ERC20'

    def process(self, neon_tx: GasTankTxInfo) -> Optional[NeonAddress]:
        if not self._has_token_whitelist:
            return None

        for event in neon_tx.iter_event_list():
            if len(event.topic_list) != 3:
                continue

            if (event.topic_list[0] != TRANSFER_EVENT) or (event.topic_list[1] != 32 * b'\0'):
                continue

            token_id = event.checksum_address.lower()
            amount = int.from_bytes(event.data, 'big')
            if self._is_allowed_token(token_id, amount):
                continue

            to = NeonAddress.from_raw(event.topic_list[2][12:])
            LOG.info(f'Common ERC20 bridge transfer: {amount} of {token_id} token to {to.checksum_address}')
            return to
        return None
