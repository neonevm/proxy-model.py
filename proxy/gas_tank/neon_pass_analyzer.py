import logging
import base58

from construct import Struct, Bytes, BytesInteger
from typing import Dict, Any, List, Tuple, Optional

from .gas_tank_types import GasTankSolTxAnalyzer

from ..common_neon.address import NeonAddress
from ..common_neon.constants import ACCOUNT_SEED_VERSION, EVM_PROGRAM_ID, TOKEN_PROGRAM_ID
from ..common_neon.utils.eth_proto import NeonTx
from ..common_neon.utils import NeonTxInfo
from ..common_neon.solana_tx import SolPubKey
from ..common_neon.solana_neon_tx_receipt import SolNeonTxReceiptInfo, SolTxMetaInfo, SolIxMetaInfo
from ..common_neon.utils.evm_log_decoder import decode_log_list, NeonLogTxReturn


LOG = logging.getLogger(__name__)

EVM_PROGRAM_CREATE_ACCT = 0x28
EVM_PROGRAM_CALL_FROM_RAW_TRX = 0x1f

TOKEN_APPROVE = 0x04
TOKEN_INIT_ACCT_2 = 0x10
TOKEN_TRANSFER = 0x03

CLAIM_TO_METHOD_ID = bytes.fromhex('67d1c218')

ClaimTo = Struct(
    'method' / Bytes(4),
    'fromAddress' / Bytes(32),
    '_toAddressZeroPrefix' / Bytes(12),
    'toAddress' / Bytes(20),
    'amount' / BytesInteger(32)
)


NPSolTx = Dict[str, Any]
NPSolIx = Dict[str, Any]


class NPTxParser:
    def __init__(self, tx: NPSolTx):
        self._block_slot = tx['slot']
        self._sol_tx_meta = SolTxMetaInfo.from_tx_receipt(self._block_slot, tx)
        self._sol_neon_tx = SolNeonTxReceiptInfo.from_tx_meta(self._sol_tx_meta)

    @property
    def acct_key_list(self) -> List[str]:
        return self._sol_tx_meta.account_key_list

    @staticmethod
    def _is_req_ix(ix_meta: SolIxMetaInfo, req_prg_id: SolPubKey, req_tag_id: int) -> bool:
        return ix_meta.is_program(req_prg_id) and ix_meta.ix_data[0] == req_tag_id

    def find_ix_list(self, caption: str, prg_id: SolPubKey, tag_id: int) -> List[Tuple[int, NPSolIx]]:
        ix_list = [
            (ix_meta.idx, ix_meta.ix)
            for ix_meta in self._sol_tx_meta.ix_meta_list
            if self._is_req_ix(ix_meta, prg_id, tag_id)
        ]
        if len(ix_list) == 0:
            LOG.debug(f'instructions for {caption} not found')
        return ix_list

    def find_inner_ix(self, caption: str, ix_idx: int, prg_id: SolPubKey, tag_id: int) -> Optional[NPSolIx]:
        ix_meta = self._sol_tx_meta.ix_meta_list[ix_idx]
        for ix_meta in self._sol_tx_meta.inner_ix_meta_list(ix_meta):
            if self._is_req_ix(ix_meta, prg_id, tag_id):
                return ix_meta.ix

        LOG.debug(f'Inner instruction {caption} for instruction {ix_idx} not found')
        return None

    def find_neon_tx_receipt(self, ix_idx: int) -> Optional[NeonLogTxReturn]:
        log_state = self._sol_neon_tx.get_ix_log_state(ix_idx, None)
        if log_state is None:
            return None
        log_info = decode_log_list(log_state.iter_str_log_msg())
        return log_info.neon_tx_return


class NeonPassAnalyzer(GasTankSolTxAnalyzer):
    name = 'NeonPass'

    def _check_on_neon_pass_tx(self, tx: NPSolTx) -> List[Tuple[NeonAddress, NeonTxInfo]]:
        tx_parser = NPTxParser(tx)
        approved_list: List[Tuple[NeonAddress, NeonTxInfo]] = list()

        # Finding instructions specific for neon-pass
        # NeonPass generates the sequence:
        # neon.CreateAccount -> token.Approve -> neon.callFromRawEthereumTrx (call claim method of ERC20)
        # Additionally:
        # call instruction internally must:
        #   1. Create token account (token.init_v2)
        #   2. Transfer tokens (token.transfer)
        # First: select all instructions that can form such chains
        create_ix_list = self._find_evm_ix_list(tx_parser, 'create account', EVM_PROGRAM_CREATE_ACCT)
        if not len(create_ix_list):
            return approved_list

        approve_ix_list = self._find_token_ix_list(tx_parser, 'approve', TOKEN_APPROVE)
        if not len(approve_ix_list):
            return approved_list

        call_ix_list = self._find_evm_ix_list(tx_parser, 'call', EVM_PROGRAM_CALL_FROM_RAW_TRX)
        if not len(call_ix_list):
            return approved_list

        for _create_idx, create_ix in create_ix_list:
            for _approve_idx, approve_ix in approve_ix_list:
                for _call_idx, call_ix in call_ix_list:
                    if (_create_idx > _approve_idx) or (_approve_idx > _call_idx):
                        LOG.debug('wrong order')
                        continue

                    init_token2_ix = self._find_token_inner_ix(tx_parser, 'init_token2', _call_idx, TOKEN_INIT_ACCT_2)
                    if init_token2_ix is None:
                        continue

                    transfer_ix = self._find_token_inner_ix(tx_parser, 'token_transfer', _call_idx, TOKEN_TRANSFER)
                    if transfer_ix is None:
                        continue

                    if not self._check_init_token2_transfer_ix(init_token2_ix, transfer_ix):
                        continue

                    neon_tx = self._get_neon_tx(tx_parser, create_ix, approve_ix, _call_idx, call_ix)
                    if neon_tx is None:
                        continue

                    account = NeonAddress(base58.b58decode(create_ix['data'])[1:][:20])
                    approved_list.append((account, neon_tx))

        return approved_list

    @staticmethod
    def _find_evm_ix_list(tx_parser: NPTxParser, caption: str, tag_id: int) -> List[Tuple[int, NPSolIx]]:
        return tx_parser.find_ix_list(caption, EVM_PROGRAM_ID, tag_id)

    @staticmethod
    def _find_token_ix_list(tx_parser: NPTxParser, caption: str, tag_id: int) -> List[Tuple[int, NPSolIx]]:
        return tx_parser.find_ix_list(caption, TOKEN_PROGRAM_ID, tag_id)

    @staticmethod
    def _find_token_inner_ix(tx_parser: NPTxParser, caption: str, ix_idx: int, tag_id: int) -> Optional[NPSolIx]:
        return tx_parser.find_inner_ix(caption, ix_idx, TOKEN_PROGRAM_ID, tag_id)

    def _get_neon_tx(self, tx_parser: NPTxParser,
                     create_acct_ix: NPSolIx,
                     approve_ix: NPSolIx,
                     call_idx: int,
                     call_ix: NPSolIx) -> Optional[NeonTxInfo]:
        # Must use the same Operator account
        approve_acct_idx = approve_ix['accounts'][2]
        call_acct_idx = call_ix['accounts'][0]
        if approve_acct_idx != call_acct_idx:
            LOG.debug(f'approve_account [{approve_acct_idx}] != call_account [{call_acct_idx}]')
            return None

        neon_return = tx_parser.find_neon_tx_receipt(call_idx)
        if (neon_return is None) or (neon_return.status != 1):
            LOG.debug('bad receipt of tx')
            return None

        data = base58.b58decode(call_ix['data'])
        try:
            neon_tx = NeonTx.from_string(data[5:])
        except (Exception,):
            LOG.debug('bad transaction')
            return None

        erc20 = neon_tx.toAddress
        try:
            claim_to = ClaimTo.parse(neon_tx.callData)
        except (Exception,):
            LOG.debug('error on unpack data')
            return None

        if claim_to.method != CLAIM_TO_METHOD_ID:
            LOG.debug('bad method')
            return None

        created_acct = base58.b58decode(create_acct_ix['data'])[1:][:20]
        if created_acct != claim_to.toAddress:
            LOG.debug(f'Created account {created_acct.hex()} and target {claim_to.toAddress.hex()} are different')
            return None

        sol_caller, _ = SolPubKey.find_program_address(
            [ACCOUNT_SEED_VERSION, b'AUTH', erc20, bytes(12) + neon_tx.sender],
            EVM_PROGRAM_ID
        )
        if SolPubKey.from_string(tx_parser.acct_key_list[approve_ix['accounts'][1]]) != sol_caller:
            LOG.debug(f"{tx_parser.acct_key_list[approve_ix['accounts'][1]]} != {sol_caller}")
            return None

        # CreateERC20TokenAccount instruction must use ERC20-wrapper from whitelist
        if not self._is_allowed_contract('0x' + erc20.hex(), claim_to.amount):
            LOG.debug(f'0x{erc20.hex()} ({claim_to.amount}) is not whitelisted ERC20 contract')
            return None

        claim_key = base58.b58decode(tx_parser.acct_key_list[approve_ix['accounts'][0]])
        if claim_key != claim_to.fromAddress:
            LOG.debug(
                f'Claim token account 0x{claim_key.hex()} != '
                f'approved token account 0x{claim_to.fromAddress.hex()}'
            )
            return None

        return NeonTxInfo.from_neon_tx(neon_tx)

    @staticmethod
    def _check_init_token2_transfer_ix(init_token2_ix: Dict[str, Any],
                                       transfer_ix: Dict[str, Any]) -> bool:
        created_acct_idx = init_token2_ix['accounts'][0]
        transfer_target_acct_idx = transfer_ix['accounts'][1]

        if created_acct_idx != transfer_target_acct_idx:
            LOG.debug(f'created_account [{created_acct_idx}] != transfer_account [{transfer_target_acct_idx}]')
            return False

        return True

    def process(self, tx: Dict[str, Any]) -> List[Tuple[NeonAddress, NeonTxInfo]]:
        if not self._has_token_whitelist:
            return list()

        return self._check_on_neon_pass_tx(tx)
