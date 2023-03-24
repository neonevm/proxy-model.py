from .airdropper import AirdropperState, AirdropperTrxAnalyzer, AirdropperTxInfo
from ..common_neon.address import NeonAddress
from typing import Set

import logging

LOG = logging.getLogger(__name__)

# keccak256("Transfer(address,address,uint256)")
TRANSFER_EVENT = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'

class CommonERC20BridgeAnalyzer(AirdropperTrxAnalyzer):
    # tokens_whitelist - the whiltelist of tokens for the transfer of which
    #   to airdrop NEONs. This set should contains ERC20 addresses separated by comma.
    # If tokens_whitelist is empty then any token transfer lead to airdrop
    def __init__(self, tokens_whitelist: Set[str]):
        self.tokens_whitelist = tokens_whitelist
        pass

    def process(self, neon_tx: AirdropperTxInfo, state: AirdropperState):
        callData = bytes.fromhex(neon_tx._neon_receipt.neon_tx.calldata[2:])
        LOG.debug(f'callData: {callData.hex()}')
        
        for event in neon_tx.iter_events():
            if len(event['topics']) == 3 and event['topics'][0] == TRANSFER_EVENT and event['topics'][1] == '0x' + 64*'0':
                tokenID = event['address']
                if len(self.tokens_whitelist) == 0 or tokenID in self.tokens_whitelist:
                    to = NeonAddress(bytes.fromhex(event['topics'][2][2:])[12:])
                    amount = int.from_bytes(bytes.fromhex(event['data'][2:]), 'big')
                    LOG.info(f'Common ERC20 bridge transfer: {amount} of {tokenID} token to {to}')
                    state.schedule_airdrop(to)
