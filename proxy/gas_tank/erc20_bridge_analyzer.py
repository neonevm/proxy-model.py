import logging

from typing import Optional

from ..common_neon.address import NeonAddress

from .gas_tank_types import GasTankNeonTxAnalyzer, GasTankTxInfo


LOG = logging.getLogger(__name__)

# keccak256("Transfer(address,address,uint256)")
TRANSFER_EVENT = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'


class ERC20Analyzer(GasTankNeonTxAnalyzer):
    name = 'ERC20'

    def process(self, neon_tx: GasTankTxInfo) -> Optional[NeonAddress]:
        if not self._has_token_whitelist:
            return None

        call_data = bytes.fromhex(neon_tx.neon_tx.calldata[2:])
        LOG.debug(f'callData: {call_data.hex()}')

        for event in neon_tx.iter_events():
            if len(event['topics']) != 3:
                continue

            if event['topics'][0] != TRANSFER_EVENT or event['topics'][1] != '0x' + 64*'0':
                continue

            token_id = event['address']
            amount = int.from_bytes(bytes.fromhex(event['data'][2:]), 'big')
            if self._is_allowed_token(token_id, amount):
                continue

            to = NeonAddress.from_raw(bytes.fromhex(event['topics'][2][2:])[12:])
            LOG.info(f'Common ERC20 bridge transfer: {amount} of {token_id} token to {to}')
            return to
        return None
