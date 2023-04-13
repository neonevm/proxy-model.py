import requests
import base58
import logging
import psycopg2.extensions
from typing import Dict, Iterator, Optional, Any
import dataclasses

from datetime import datetime
from decimal import Decimal

from ..common_neon.address import NeonAddress
from ..common_neon.config import Config
from ..common_neon.constants import ACCOUNT_SEED_VERSION
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.eth_proto import NeonTx
from ..common_neon.solana_tx import SolPubKey
from ..common_neon.pythnetwork import PythNetworkClient
from ..common_neon.solana_neon_tx_receipt import SolTxReceiptInfo, SolNeonIxReceiptInfo
from ..common_neon.utils.neon_tx_info import NeonTxInfo
from ..common_neon.evm_log_decoder import NeonLogTxEvent

from ..indexer.indexed_objects import NeonIndexedHolderInfo, NeonIndexedTxInfo
from ..indexer.indexer_base import IndexerBase
from ..indexer.solana_tx_meta_collector import SolTxMetaDict, FinalizedSolTxMetaCollector
from ..indexer.base_db import BaseDB
from ..indexer.utils import check_error
from ..indexer.sql_dict import SQLDict


LOG = logging.getLogger(__name__)

EVM_LOADER_CALL_FROM_RAW_TRX                = 0x1f
EVM_LOADER_STEP_FROM_RAW_TRX                = 0x20
EVM_LOADER_HOLDER_WRITE                     = 0x26
EVM_LOADER_CREATE_ACC                       = 0x28
EVM_LOADER_TRX_STEP_FROM_ACCOUNT            = 0x21
EVM_LOADER_TRX_STEP_FROM_ACCOUNT_NO_CHAINID = 0x22
EVM_LOADER_CANCEL                           = 0x23
EVM_LOADER_TRX_EXECUTE_FROM_ACCOUNT         = 0x2A

SPL_TOKEN_APPROVE                = 0x04
SPL_TOKEN_INIT_ACC_2             = 0x10
SPL_TOKEN_TRANSFER               = 0x03

ACCOUNT_CREATION_PRICE_SOL = Decimal('0.00472692')
AIRDROP_AMOUNT_SOL = ACCOUNT_CREATION_PRICE_SOL / 2

CLAIM_TO_METHOD_ID = bytes.fromhex('67d1c218')


class FailedAttempts(BaseDB):
    def __init__(self) -> None:
        super().__init__('failed_airdrop_attempts', [])
        self._conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

    def airdrop_failed(self, eth_address, reason):
        with self._conn.cursor() as cur:
            cur.execute(f'''
            INSERT INTO {self._table_name} (attempt_time, eth_address, reason)
            VALUES (%s, %s, %s)''',
            (datetime.now().timestamp(), eth_address, reason))


class AirdropReadySet(BaseDB):
    def __init__(self):
        super().__init__('airdrop_ready', [])
        self._conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

    def register_airdrop(self, eth_address: str, airdrop_info: dict):
        finished = int(datetime.now().timestamp())
        duration = finished - airdrop_info['scheduled']
        with self._conn.cursor() as cur:
            cur.execute(f'''
            INSERT INTO {self._table_name} (eth_address, scheduled_ts, finished_ts, duration, amount_galans)
            VALUES (%s, %s, %s, %s, %s)''',
            (eth_address, airdrop_info['scheduled'], finished, duration, airdrop_info['amount']))

    def is_airdrop_ready(self, eth_address):
        with self._conn.cursor() as cur:
            cur.execute(f"SELECT 1 FROM {self._table_name} WHERE eth_address = %s", (eth_address,))
            return cur.fetchone() is not None

class AirdropperTxInfo(NeonIndexedTxInfo):
    def __init__(self, type: NeonIndexedTxInfo.Type, key: NeonIndexedTxInfo.Key, neon_tx: NeonTxInfo,
                 holder: str, iter_blocked_account: Iterator[str]):
        super().__init__(type, key, neon_tx, holder, iter_blocked_account)
        self.iterations: Dict[int,int] = {}

    @staticmethod
    def create_tx_info(sol_sig: str, neon_tx_sig: str, message: bytes, type: NeonIndexedTxInfo.Type, key: NeonIndexedTxInfo.Key,
                                holder: str, iter_blocked_account: Iterator[str]) -> Optional[NeonIndexedTxInfo]:
        neon_tx = NeonTxInfo.from_sig_data(message)
        if neon_tx.error:
            LOG.warning(f'{sol_sig} Neon tx rlp error "{neon_tx.error}"')
            return None
        if neon_tx_sig != neon_tx.sig:
            LOG.warning(f'{sol_sig} Neon tx hash {neon_tx.sig} != {neon_tx_sig}')
            return None

        return AirdropperTxInfo(type, key, neon_tx, holder, iter_blocked_account)

    def append_receipt(self, ix: SolNeonIxReceiptInfo):
        self.iterations[ix.neon_total_gas_used] = ix.neon_gas_used
        self.add_sol_neon_ix(ix)
        total_gas_used = ix.neon_total_gas_used
        for event in ix.neon_tx_event_list:
            self.add_neon_event(dataclasses.replace(
                event,
                total_gas_used=total_gas_used,
                sol_sig=ix.sol_sig,
                idx=ix.idx,
                inner_idx=ix.inner_idx
            ))
            total_gas_used += 1

        if ix.neon_tx_return is not None:
            self.neon_tx_res.set_res(status=ix.neon_tx_return.status, gas_used=ix.neon_tx_return.gas_used)
            self.neon_tx_res.set_sol_sig_info(ix.sol_sig, ix.idx, ix.inner_idx)
            self.add_neon_event(NeonLogTxEvent(
                event_type=NeonLogTxEvent.Type.Return,
                is_hidden=True, address=b'', topic_list=[],
                data=ix.neon_tx_return.status.to_bytes(1,'little'),
                total_gas_used=ix.neon_tx_return.gas_used+5000,
                sol_sig=ix.sol_sig, idx=ix.idx, inner_idx=ix.inner_idx
            ))
            self.set_status(AirdropperTxInfo.Status.Done, ix.block_slot)

    def finalize(self):
        total_gas_used = 0
        for k,v in sorted(self.iterations.items()):
            if total_gas_used + v != k:
                raise Exception(f'{self.key} not all iterations were collected {sorted(self.iterations.items())}')
            total_gas_used += v

        self.complete_event_list()

    def iter_events(self) -> Iterator[Dict[str,Any]]:
        for ev in self.neon_tx_res.log_list:
            if ev['neonIsHidden']==False:
                yield ev

# Interface class for work with airdropper state from analyzers objects
class AirdropperState:
    # Schedule airdrop for the specified address
    # It is no second airdrop if one was scheduled to this address.
    def schedule_airdrop(self, address: NeonAddress):
        pass

# Base class to create NeonEVM transaction analyzers for airdropper
class AirdropperTrxAnalyzer:
    # Function to process NeonEVM transaction to find one that should be rewarded with airdrop
    # Arguments:
    #  - neon_tx - information about NeonEVM transaction
    #  - state - airdropper state
    def process(self, neon_tx: AirdropperTxInfo, state: AirdropperState):
        pass

class Airdropper(IndexerBase, AirdropperState):
    def __init__(self,
                 config: Config,
                 faucet_url='',
                 wrapper_whitelist = 'ANY',
                 analyzers: Dict[NeonAddress,AirdropperTrxAnalyzer]={},
                 max_conf = 0.1): # maximum confidence interval deviation related to price
        self._constants = SQLDict(tablename="constants")

        solana = SolInteractor(config, config.solana_url)
        last_known_slot = self._constants.get('latest_processed_slot', None)
        super().__init__(config, solana, last_known_slot)
        self.latest_processed_slot = self._start_slot
        self.current_slot = 0
        sol_tx_meta_dict = SolTxMetaDict()
        self._sol_tx_collector = FinalizedSolTxMetaCollector(config, self._solana, sol_tx_meta_dict, self._start_slot)

        # collection of eth-address-to-create-accout-trx mappings
        # for every addresses that was already funded with airdrop
        self.airdrop_ready = AirdropReadySet()
        self.failed_attempts = FailedAttempts()
        self.airdrop_scheduled = SQLDict(tablename="airdrop_scheduled")
        self.wrapper_whitelist = wrapper_whitelist
        if isinstance(self.wrapper_whitelist, list):
            self.wrapper_whitelist = [str(entry).lower() for entry in self.wrapper_whitelist]

        self.faucet_url = faucet_url
        self.recent_price = None

        # It is possible to use different networks to obtain SOL price
        # but there will be different slot numbers so price should be updated every time
        self.always_reload_price = config.solana_url != config.pyth_solana_url
        self.pyth_client = PythNetworkClient(SolInteractor(config, config.pyth_solana_url))
        self.max_conf = Decimal(max_conf)
        self.session = requests.Session()

        self.sol_price_usd = None
        self.airdrop_amount_usd = None
        self.airdrop_amount_neon = None
        self.last_update_pyth_mapping = None
        self.max_update_pyth_mapping_int = 60 * 60  # update once an hour
        self.neon_large_tx: Dict[str, NeonIndexedHolderInfo] = {}
        self.neon_processed_tx: Dict[str, AirdropperTxInfo] = {}
        self.last_finalized_slot: int = 0
        self.analyzers: Dict[str, AirdropperTrxAnalyzer] = analyzers


    @staticmethod
    def get_current_time():
        return datetime.now().timestamp()

    def try_update_pyth_mapping(self):
        current_time = self.get_current_time()
        if self.last_update_pyth_mapping is None or abs(current_time - self.last_update_pyth_mapping) > self.max_update_pyth_mapping_int:
            try:
                self.pyth_client.update_mapping(self._config.pyth_mapping_account)
                self.last_update_pyth_mapping = current_time
            except BaseException as exc:
                LOG.error('Failed to update pyth.network mapping account data', exc_info=exc)
                return False

        return True

    # helper function checking if given contract address is in whitelist
    def is_allowed_wrapper_contract(self, contract_addr: str):
        if self.wrapper_whitelist == 'ANY':
            return True
        return contract_addr.lower() in self.wrapper_whitelist

    # helper function checking if given 'approve' corresponds to 'call' instruction
    def check_create_approve_call_instr(self, account_keys, create_acc, approve, call):
        # Must use the same Operator account
        if account_keys[approve['accounts'][2]] != account_keys[call['accounts'][0]]:
            return False

        data = base58.b58decode(call['data'])
        try:
            tx = NeonTx.from_string(data[5:])
        except (Exception, ):
            LOG.debug('bad transaction')
            return False

        caller = tx.sender
        erc20 = tx.toAddress
        method_id = tx.callData[:4]
        source_token = tx.callData[4:36]
        target_neon_acc = tx.callData[48:68]

        created_account = base58.b58decode(create_acc['data'])[1:][:20]
        if created_account != target_neon_acc:
            LOG.debug(f"Created account {created_account.hex()} and target {target_neon_acc.hex()} are different")
            return False

        sol_caller, _ = SolPubKey.find_program_address([ACCOUNT_SEED_VERSION, b"AUTH", erc20, bytes(12) + caller], self._config.evm_loader_id)
        if SolPubKey.from_string(account_keys[approve['accounts'][1]]) != sol_caller:
            LOG.debug(f"account_keys[approve['accounts'][1]] != sol_caller")
            return False

        # CreateERC20TokenAccount instruction must use ERC20-wrapper from whitelist
        if not self.is_allowed_wrapper_contract("0x" + erc20.hex()):
            LOG.debug(f"{erc20.hex()} Is not whitelisted ERC20 contract")
            return False

        if method_id != CLAIM_TO_METHOD_ID:
            LOG.debug(f'bad method: {method_id}')
            return False

        claim_key = base58.b58decode(account_keys[approve['accounts'][0]])
        if claim_key != source_token:
            LOG.debug(f"Claim token account {claim_key.hex()} != approve token account {source_token.hex()}")
            return False

        return True

    def check_inittoken2_transfer_instr(
        self,
        account_keys,
        init_token2_instr,
        transfer_instr
    ):
        created_account = account_keys[init_token2_instr['accounts'][0]]
        transfer_target_acc = account_keys[transfer_instr['accounts'][1]]

        if created_account != transfer_target_acc:
            LOG.debug(f"created_account [{created_account}] != transfer_target_acc [{transfer_target_acc}]")
            return False

        return True

    def airdrop_to(self, eth_address, airdrop_galans):
        LOG.info(f"Airdrop {airdrop_galans} Galans to address: {eth_address}")
        json_data = {'wallet': eth_address, 'amount': airdrop_galans}
        resp = self.session.post(self.faucet_url + '/request_neon_in_galans', json=json_data)
        if not resp.ok:
            LOG.warning(f'Failed to airdrop: {resp.status_code}')
            return False

        return True

    # Method to process NeonEVM transaction extracted from the instructions
    def process_neon_transaction(self, tx_info: AirdropperTxInfo):
        if tx_info.status != AirdropperTxInfo.Status.Done or tx_info.neon_tx_res.status != '0x1':
            LOG.debug(f'SKIPPED {tx_info.key} status {tx_info.status} result {tx_info.neon_tx_res.status}: {tx_info}')
            return

        try:
            tx_info.finalize()
            trx = tx_info._neon_receipt.neon_tx
            sender = trx.addr
            to = NeonAddress(trx.to_addr) if trx.to_addr is not None else None
            LOG.debug(f"from: {sender}, to: {to}, calldata: {trx.calldata}")
            analyzer = self.analyzers.get(to, None)
            if analyzer is not None:
                analyzer.process(tx_info, self)
        except Exception as error:
            LOG.warning(f"Failed to analyze {tx_info.key}: {error}")


    # Method to process Solana transactions and extract NeonEVM transaction from the contract instructions.
    # For large NeonEVM transaction that passing to contract via account data, this method extracts and
    # combines chunk of data from different HolderWrite instructions. At the any time `neon_large_tx`
    # dictionary contains actual NeonEVM transactions written into the holder accounts. The stored account
    # are cleared in case of execution, cancel trx or writing chunk of data from another NeonEVM transaction.
    # This logic are implemented according to the work with holder account inside contract.
    # Note: the `neon_large_tx` dictionary stored only in memory, so `last_processed_slot` move forward only
    # after finalize corresponding holder account. It is necessary for correct transaction processing after
    # restart the airdriop service.
    # Note: this implementation analyzes only the final step in case of iterative execution. It simplifies it
    # but does not process events generated from the Solidity contract.
    def process_trx_neon_instructions(self, trx):
        if check_error(trx):
            return

        tx_receipt_info = SolTxReceiptInfo.from_tx(trx)
        sol_sig = tx_receipt_info.sol_sig

        if self.last_finalized_slot < tx_receipt_info.block_slot:
            self.last_finalized_slot = tx_receipt_info.block_slot
            finalized_trx = [k for k,v in self.neon_processed_tx.items() if v.status != AirdropperTxInfo.Status.InProgress and v.last_block_slot < tx_receipt_info.block_slot]
            if len(finalized_trx):
                LOG.debug(f'Finalized: {finalized_trx}')
                for k in finalized_trx:
                    tx_info = self.neon_processed_tx.pop(k)
                    self.process_neon_transaction(tx_info)

        for sol_neon_ix in tx_receipt_info.iter_sol_neon_ix():
            instruction = sol_neon_ix.ix_data[0]
            LOG.debug(f"{sol_sig} instruction: {instruction} {sol_neon_ix.neon_tx_sig}")
            LOG.debug(f"INSTRUCTION: {sol_neon_ix}")
            if instruction == EVM_LOADER_HOLDER_WRITE:
                neon_tx_id = NeonIndexedHolderInfo.Key(sol_neon_ix.get_account(0), sol_neon_ix.neon_tx_sig)
                data = sol_neon_ix.ix_data[41:]
                chunk = NeonIndexedHolderInfo.DataChunk(
                    offset=int.from_bytes(sol_neon_ix.ix_data[33:41],'little'),
                    length=len(data),
                    data=data
                )
                neon_tx_data = self.neon_large_tx.get(neon_tx_id.value, None)
                if neon_tx_data is None:
                    LOG.debug(f"{sol_sig} New NEON trx: {neon_tx_id} {len(chunk.data)} bytes at {chunk.offset}")
                    neon_tx_data = NeonIndexedHolderInfo(neon_tx_id)
                    self.neon_large_tx[neon_tx_id.value] = neon_tx_data
                neon_tx_data.add_data_chunk(chunk)
                neon_tx_data.add_sol_neon_ix(sol_neon_ix)

            elif instruction in [EVM_LOADER_TRX_STEP_FROM_ACCOUNT,
                                 EVM_LOADER_TRX_STEP_FROM_ACCOUNT_NO_CHAINID,
                                 EVM_LOADER_TRX_EXECUTE_FROM_ACCOUNT]:
                key = AirdropperTxInfo.Key(sol_neon_ix)
                tx_info = self.neon_processed_tx.get(key.value, None)
                if tx_info is not None:
                    tx_info.append_receipt(sol_neon_ix)
                    continue

                neon_tx_id = NeonIndexedHolderInfo.Key(sol_neon_ix.get_account(0), sol_neon_ix.neon_tx_sig)
                neon_tx_data = self.neon_large_tx.pop(neon_tx_id.value, None)
                if neon_tx_data is None:
                    LOG.warning(f"{sol_sig} Holder account {neon_tx_id} is not in the collected data")
                    continue

                type = {
                    EVM_LOADER_TRX_STEP_FROM_ACCOUNT:            AirdropperTxInfo.Type.IterFromAccount,
                    EVM_LOADER_TRX_STEP_FROM_ACCOUNT_NO_CHAINID: AirdropperTxInfo.Type.IterFromAccountWoChainId,
                    EVM_LOADER_TRX_EXECUTE_FROM_ACCOUNT:         AirdropperTxInfo.Type.SingleFromAccount,
                }.get(instruction)
                first_blocked_account = 6
                tx_info = AirdropperTxInfo.create_tx_info(
                    sol_sig, sol_neon_ix.neon_tx_sig, neon_tx_data.data, type, key,
                    sol_neon_ix.get_account(0), sol_neon_ix.iter_account(first_blocked_account)
                )
                if tx_info is None:
                    continue
                tx_info.append_receipt(sol_neon_ix)

                if instruction == EVM_LOADER_TRX_EXECUTE_FROM_ACCOUNT:
                    if tx_info.status != AirdropperTxInfo.Status.Done:
                        LOG.warning(f"{sol_sig} No tx_return for single call")
                    else:
                        self.process_neon_transaction(tx_info)
                else:
                    self.neon_processed_tx[key.value] = tx_info

            if instruction == EVM_LOADER_CALL_FROM_RAW_TRX:
                if len(sol_neon_ix.ix_data) < 6:
                    LOG.warning(f'{sol_sig} no enough data to get Neon tx')
                    continue

                tx_info = AirdropperTxInfo.create_tx_info(
                    sol_sig, sol_neon_ix.neon_tx_sig, sol_neon_ix.ix_data[5:],
                    AirdropperTxInfo.Type.Single, AirdropperTxInfo.Key(sol_neon_ix),
                    '', iter(())
                )
                if tx_info is None:
                    continue
                tx_info.append_receipt(sol_neon_ix)

                if tx_info.status != AirdropperTxInfo.Status.Done:
                    LOG.warning(f"{sol_sig} No tx_return for single call")
                    continue

                self.process_neon_transaction(tx_info)

            elif instruction == EVM_LOADER_STEP_FROM_RAW_TRX:
                key = AirdropperTxInfo.Key(sol_neon_ix)
                tx_info = self.neon_processed_tx.get(key.value, None)
                if tx_info is None:
                    first_blocked_account = 6
                    if len(sol_neon_ix.ix_data) < 14 or sol_neon_ix.account_cnt < first_blocked_account+1:
                        LOG.warning(f'{sol_sig} no enough data or accounts to get Neon tx')
                        continue

                    tx_info = AirdropperTxInfo.create_tx_info(
                        sol_sig, sol_neon_ix.neon_tx_sig, sol_neon_ix.ix_data[13:],
                        AirdropperTxInfo.Type.IterFromData, key,
                        sol_neon_ix.get_account(0), sol_neon_ix.iter_account(first_blocked_account)
                    )
                    if tx_info is None:
                        continue
                    self.neon_processed_tx[key.value] = tx_info

                tx_info.append_receipt(sol_neon_ix)

            elif instruction == EVM_LOADER_CANCEL:
                key = AirdropperTxInfo.Key(sol_neon_ix)
                tx_info = self.neon_processed_tx.get(key.value, None)
                if tx_info is None:
                    LOG.warning(f'{sol_sig} Cancel unknown trx {key}')
                    continue
                tx_info.set_status(AirdropperTxInfo.Status.Canceled, sol_neon_ix.block_slot)

    def process_trx_airdropper_mode(self, trx):
        if check_error(trx):
            return

        LOG.debug(f"Processing transaction: {trx}")

        # helper function finding all instructions that satisfies predicate
        def find_instructions(instructions, predicate):
            return [(number, instr) for number, instr in instructions if predicate(instr)]

        def find_inner_instructions(trx, instr_idx, predicate):
            inner_instructions = None
            for entry in trx['meta']['innerInstructions']:
                if entry['index'] == instr_idx:
                    inner_instructions = entry['instructions']
                    break

            if inner_instructions is None:
                LOG.debug(f'Inner instructions for instruction {instr_idx} not found')
                return []

            return [instruction for instruction in inner_instructions if predicate(instruction)]

        def isRequiredInstruction(instr, req_program_id, req_tag_id):
            return account_keys[instr['programIdIndex']] == str(req_program_id) \
                and base58.b58decode(instr['data'])[0] == req_tag_id

        account_keys = trx["transaction"]["message"]["accountKeys"]
        lookup_keys = trx["meta"].get('loadedAddresses', None)
        if lookup_keys is not None:
            account_keys += lookup_keys['writable'] + lookup_keys['readonly']

        instructions = [(number, entry) for number, entry in enumerate(trx['transaction']['message']['instructions'])]

        # Finding instructions specific for airdrop.
        # Airdrop triggers on sequence:
        # neon.CreateAccount -> token.Approve -> neon.callFromRawEthereumTrx (call claim method of ERC20)
        # Additionaly:
        # call instruction internally must:
        #   1. Create token account (token.init_v2)
        #   2. Transfer tokens (token.transfer)
        # First: select all instructions that can form such chains
        predicate = lambda instr: isRequiredInstruction(instr, self._config.evm_loader_id, EVM_LOADER_CREATE_ACC)
        create_acc_list = find_instructions(instructions, predicate)
        LOG.debug(f'create_acc_list: {create_acc_list}')

        predicate = lambda  instr: isRequiredInstruction(instr, 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', SPL_TOKEN_APPROVE)
        approve_list = find_instructions(instructions, predicate)
        LOG.debug(f'approve_list: {approve_list}')

        predicate = lambda  instr: isRequiredInstruction(instr, self._config.evm_loader_id, EVM_LOADER_CALL_FROM_RAW_TRX)
        call_list = find_instructions(instructions, predicate)
        LOG.debug(f'call_list: {call_list}')

        # Second: Find exact chains of instructions in sets created previously
        for create_acc_idx, create_acc in create_acc_list:
            LOG.debug(f"Processing create_acc[{create_acc_idx}]")
            for approve_idx, approve in approve_list:
                LOG.debug(f"Processing approve[{approve_idx}]")
                for call_idx, call in call_list:
                    LOG.debug(f"Processing call[{call_idx}]")
                    if not self.check_create_approve_call_instr(account_keys, create_acc, approve, call):
                        continue

                    predicate = lambda  instr: isRequiredInstruction(instr, 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', SPL_TOKEN_INIT_ACC_2)
                    init_token2_list = find_inner_instructions(trx, call_idx, predicate)

                    LOG.debug(f'init_token2_list = {init_token2_list}')
                    if len(init_token2_list) != 1:
                        LOG.debug(f"Expected exactly one inner inittoken2 instruction")
                        continue

                    predicate = lambda  instr: isRequiredInstruction(instr, 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', SPL_TOKEN_TRANSFER)
                    token_transfer_list = find_inner_instructions(trx, call_idx, predicate)

                    LOG.debug(f'token_transfer_list = {token_transfer_list}')
                    if len(token_transfer_list) != 1:
                        LOG.debug(f"expected exactly one inner transfer instruction")
                        continue

                    init_token2 = init_token2_list[0]
                    token_transfer = token_transfer_list[0]
                    check_res = self.check_inittoken2_transfer_instr(
                        account_keys,
                        init_token2,
                        token_transfer
                    )

                    if not check_res:
                        continue

                    account = NeonAddress(base58.b58decode(create_acc['data'])[1:][:20])
                    self.schedule_airdrop(account)

    def get_sol_usd_price(self):
        should_reload = self.always_reload_price
        if not should_reload:
            if self.recent_price is None or self.recent_price['valid_slot'] < self.current_slot:
                should_reload = True

        if should_reload:
            try:
                self.recent_price = self.pyth_client.get_price('Crypto.SOL/USD')
            except BaseException as exc:
                LOG.error('Exception occurred when reading price', exc_info=exc)
                return None

        return self.recent_price

    def get_airdrop_amount_galans(self):
        self.sol_price_usd = self.get_sol_usd_price()
        if self.sol_price_usd is None:
            LOG.warning("Failed to get SOL/USD price")
            return None

        neon_price_usd = self._config.neon_price_usd
        LOG.info(f"NEON price: ${neon_price_usd}")
        LOG.info(f"Price valid slot: {self.sol_price_usd['valid_slot']}")
        LOG.info(f"Price confidence interval: ${self.sol_price_usd['conf']}")
        LOG.info(f"SOL/USD = ${self.sol_price_usd['price']}")
        if self.sol_price_usd['conf'] / self.sol_price_usd['price'] > self.max_conf:
            LOG.warning(f"Confidence interval too large. Airdrops will deferred.")
            return None

        self.airdrop_amount_usd = AIRDROP_AMOUNT_SOL * self.sol_price_usd['price']
        self.airdrop_amount_neon = self.airdrop_amount_usd / neon_price_usd
        LOG.info(f"Airdrop amount: ${self.airdrop_amount_usd} ({self.airdrop_amount_neon} NEONs)\n")
        return int(self.airdrop_amount_neon * pow(Decimal(10), self._config.neon_decimals))

    def schedule_airdrop(self, account: NeonAddress):
        eth_address = str(account)
        if self.airdrop_ready.is_airdrop_ready(eth_address) or eth_address in self.airdrop_scheduled:
            # Target account already supplied with airdrop or airdrop already scheduled
            return
        LOG.info(f'Scheduling airdrop for {eth_address}')
        self.airdrop_scheduled[eth_address] = { 'scheduled': self.get_current_time() }

    def process_scheduled_trxs(self):
        # Pyth.network mapping account was never updated
        if not self.try_update_pyth_mapping() and self.last_update_pyth_mapping is None:
            self.failed_attempts.airdrop_failed('ALL', 'mapping is empty')
            return

        airdrop_galans = self.get_airdrop_amount_galans()
        if airdrop_galans is None:
            LOG.warning('Failed to estimate airdrop amount. Defer scheduled airdrops.')
            self.failed_attempts.airdrop_failed('ALL', 'fail to estimate amount')
            return

        success_addresses = set()
        for eth_address, sched_info in self.airdrop_scheduled.items():
            if not self.airdrop_to(eth_address, airdrop_galans):
                self.failed_attempts.airdrop_failed(str(eth_address), 'airdrop failed')
                continue
            success_addresses.add(eth_address)
            self.airdrop_ready.register_airdrop(eth_address,
                                                {
                                                    'amount': airdrop_galans,
                                                    'scheduled': sched_info['scheduled']
                                                })

        for eth_address in success_addresses:
            if eth_address in self.airdrop_scheduled:
                del self.airdrop_scheduled[eth_address]

    def process_functions(self):
        """
        Overrides IndexerBase.process_functions
        """
        IndexerBase.process_functions(self)
        LOG.debug("Process receipts")
        self.process_receipts()
        self.process_scheduled_trxs()

    def process_receipts(self):
        last_block_slot = self._solana.get_block_slot(self._sol_tx_collector.commitment)
        for meta in self._sol_tx_collector.iter_tx_meta(last_block_slot, self._sol_tx_collector.last_block_slot):
            self.current_slot = meta.block_slot
            if meta.tx['transaction']['message']['instructions'] is not None:
                self.process_trx_airdropper_mode(meta.tx)
                self.process_trx_neon_instructions(meta.tx)
        self.latest_processed_slot = self._sol_tx_collector.last_block_slot

        # Find the minimum start_block_slot through unfinished neon_large_tx. It is necessary for correct
        # transaction processing after restart the airdrop service. See `process_trx_neon_instructions`
        # for more information.
        outdated_holders = [tx.key for tx in self.neon_large_tx.values() if tx.last_block_slot + self._config.holder_timeout < self._sol_tx_collector.last_block_slot]
        for tx_key in outdated_holders:
            LOG.info(f"Outdated holder {tx_key}. Drop it.")
            self.neon_large_tx.pop(tx_key)

        lost_trx = [k for k,v in self.neon_processed_tx.items() if
                        v.status == AirdropperTxInfo.Status.InProgress and
                        v.last_block_slot + self._config.holder_timeout < self._sol_tx_collector.last_block_slot]
        for k in lost_trx:
            tx_info = self.neon_processed_tx.pop(k)
            LOG.warning(f'Lost trx {tx_info.key}. Drop it.')

        for tx in self.neon_large_tx.values():
            self.latest_processed_slot = min(self.latest_processed_slot, tx.start_block_slot-1)
        for tx in self.neon_processed_tx.values():
            self.latest_processed_slot = min(self.latest_processed_slot, tx.start_block_slot-1)

        self._constants['latest_processed_slot'] = self.latest_processed_slot
        LOG.debug(f"Latest processed slot: {self.latest_processed_slot}, Solana finalized slot {self._sol_tx_collector.last_block_slot}")
