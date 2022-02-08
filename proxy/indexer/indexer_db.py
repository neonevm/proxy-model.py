import base58
import traceback

from logged_groups import logged_group
from typing import Optional

from ..common_neon.utils import NeonTxInfo, NeonTxResultInfo, NeonTxFullInfo

from ..environment import FINALIZED
from ..indexer.utils import SolanaIxSignInfo
from ..indexer.accounts_db import NeonAccountDB, NeonAccountInfo
from ..indexer.blocks_db import SolanaBlocksDB, SolanaBlockInfo
from ..indexer.transactions_db import NeonTxsDB
from ..indexer.logs_db import LogsDB
from ..indexer.sql_dict import SQLDict
from ..indexer.utils import get_code_from_account, get_accounts_by_neon_address


@logged_group("neon.Indexer")
class IndexerDB:
    def __init__(self):
        self._logs_db = LogsDB()
        self._blocks_db = SolanaBlocksDB()
        self._txs_db = NeonTxsDB()
        self._account_db = NeonAccountDB()
        self._client = None

        self._constants = SQLDict(tablename="constants")
        for k in ['min_receipt_slot']:
            if k not in self._constants:
                self._constants[k] = 0

    def set_client(self, client):
        self._client = client

    def submit_transaction(self, neon_tx: NeonTxInfo, neon_res: NeonTxResultInfo, used_ixs: [SolanaIxSignInfo]):
        try:
            block = self.get_block_by_slot(neon_res.slot)
            if block.hash is None:
                self.critical(f'Unable to submit transaction {neon_tx.sign} because slot {neon_res.slot} not found')
                return
            self.debug(f'{neon_tx} {neon_res} {block}')
            neon_res.fill_block_info(block)
            self._logs_db.push_logs(neon_res.logs, block)
            tx = NeonTxFullInfo(neon_tx=neon_tx, neon_res=neon_res, used_ixs=used_ixs)
            self._txs_db.set_tx(tx)
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error('Exception on submitting transaction. ' +
                       f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')

    def _fill_block_from_net(self, block: SolanaBlockInfo):
        opts = {"commitment": FINALIZED, "transactionDetails": "signatures", "rewards": False}
        net_block = self._client._provider.make_request("getBlock", block.slot, opts)
        if (not net_block) or ('result' not in net_block):
            return block

        net_block = net_block['result']
        block.hash = '0x' + base58.b58decode(net_block['blockhash']).hex()
        block.height = net_block['blockHeight']
        block.signs = net_block['signatures']
        block.parent_hash = '0x' + base58.b58decode(net_block['previousBlockhash']).hex()
        block.time = net_block['blockTime']
        block.finalized = True
        self.debug(f'{block}')
        self._blocks_db.set_block(block)
        return block

    def _fill_account_data_from_net(self, account: NeonAccountInfo):
        got_changes = False
        if not account.pda_account:
            pda_account, code_account = get_accounts_by_neon_address(self._client, account.neon_account)
            if pda_account:
                account.pda_account = pda_account
                account.code_account = code_account
                got_changes = True
        if account.code_account:
            code = get_code_from_account(self._client, account.code_account)
            if code:
                account.code = code
                got_changes = True
        if got_changes:
            self._account_db.set_acc_by_request(
                account.neon_account,
                account.pda_account,
                account.code_account,
                account.code)
        return account

    def get_block_by_slot(self, slot) -> SolanaBlockInfo:
        block = self._blocks_db.get_block_by_slot(slot)
        if not block.hash:
            self._fill_block_from_net(block)
        return block

    def get_full_block_by_slot(self, slot) -> SolanaBlockInfo:
        block = self._blocks_db.get_full_block_by_slot(slot)
        if not block.parent_hash:
            self._fill_block_from_net(block)
        return block

    def get_latest_block(self) -> SolanaBlockInfo:
        return self._blocks_db.get_latest_block()

    def fill_block_height(self, number, slots):
        self._blocks_db.fill_block_height(number, slots)

    def get_min_receipt_slot(self) -> int:
        return self._constants['min_receipt_slot']

    def set_min_receipt_slot(self, slot):
        self._constants['min_receipt_slot'] = slot

    def get_logs(self, from_block, to_block, addresses, topics, block_hash):
        return self._logs_db.get_logs(from_block, to_block, addresses, topics, block_hash)

    def get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        return self._blocks_db.get_block_by_hash(block_hash)

    def get_block_by_height(self, block_height: int) -> SolanaBlockInfo:
        return self._blocks_db.get_block_by_height(block_height)

    def get_tx_list_by_sol_sign(self, sol_sign_list: [str]) -> [NeonTxFullInfo]:
        tx_list = self._txs_db.get_tx_list_by_sol_sign(sol_sign_list)
        block = None
        for tx in tx_list:
            if not block:
                block = self.get_block_by_slot(tx.neon_res.slot)
            tx.block = block
        return tx_list

    def get_tx_by_neon_sign(self, neon_sign: str) -> Optional[NeonTxFullInfo]:
        tx = self._txs_db.get_tx_by_neon_sign(neon_sign)
        if tx:
            tx.block = self.get_block_by_slot(tx.neon_res.slot)
        return tx

    def get_contract_code(self, address) -> str:
        account = self._account_db.get_account_info(address)
        if not account.neon_account or (account.code_account and not account.code):
            if not account.neon_account:
                account.neon_account = address
            account = self._fill_account_data_from_net(account)
        if account.code:
            return account.code
        return '0x'

    def fill_account_info_by_indexer(self, neon_account: str, pda_account: str, code_account: str, slot: int):
        self._account_db.set_acc_indexer(neon_account, pda_account, code_account, slot)
