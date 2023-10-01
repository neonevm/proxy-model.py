import logging
import math
import multiprocessing
import threading
import time

from dataclasses import dataclass
from typing import Optional, Union, Dict, Any, List, cast

import eth_utils
from eth_account import Account as NeonAccount
from sha3 import keccak_256

from ..common_neon.config import Config
from ..common_neon.constants import EVM_PROGRAM_ID_STR
from ..common_neon.data import NeonTxExecCfg
from ..common_neon.elf_params import ElfParams
from ..common_neon.errors import EthereumError, InvalidParamError, RescheduleError, NonceTooLowError
from ..common_neon.keys_storage import KeyStorage
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_neon_tx_receipt import SolNeonIxReceiptInfo, SolAltIxInfo
from ..common_neon.eth_commit import EthCommit
from ..common_neon.solana_tx import SolCommit
from ..common_neon.utils import NeonTxInfo
from ..common_neon.neon_tx_receipt_info import NeonTxReceiptInfo
from ..common_neon.neon_tx_result_info import NeonTxResultInfo
from ..common_neon.solana_block import SolBlockInfo
from ..common_neon.utils.eth_proto import NeonTx
from ..common_neon.neon_instruction import EvmIxCodeName, AltIxCodeName
from ..common_neon.db.db_connect import DBConnection

from ..mempool import (
    MemPoolClient, MP_SERVICE_ADDR,
    MPNeonTxResult, MPTxSendResult, MPTxSendResultCode, MPGasPriceResult
)

from ..neon_core_api.neon_core_api_client import NeonCoreApiClient
from ..neon_core_api.neon_layouts import NeonAccountInfo

from ..gas_tank.gas_less_accounts_db import GasLessAccountsDB
from ..indexer.indexer_db import IndexerDB

from .estimate import GasEstimate
from .transaction_validator import NeonTxValidator


NEON_PROXY_PKG_VERSION = '1.5.0-dev'
NEON_PROXY_REVISION = 'NEON_PROXY_REVISION_TO_BE_REPLACED'
LOG = logging.getLogger(__name__)


@dataclass
class OpCostInfo:
    sol_spent: int = 0
    neon_income: int = 0


def get_req_id_from_log():
    th = threading.current_thread()
    req_id = getattr(th, "log_context", {}).get("req_id", "")
    return req_id


class NeonRpcApiWorker:
    proxy_id_glob = multiprocessing.Value('i', 0)

    def __init__(self, config: Config):
        self._config = config
        self._solana = SolInteractor(config)

        db_conn = DBConnection(config)
        self._db = IndexerDB.from_db(config, db_conn)
        self._gas_tank = GasLessAccountsDB(db_conn)

        self._core_api_client = NeonCoreApiClient(config)

        self._mempool_client = MemPoolClient(MP_SERVICE_ADDR)

        self._gas_price_value: Optional[MPGasPriceResult] = None
        self._last_gas_price_time = 0

        self._last_elf_params_time = 0

        with self.proxy_id_glob.get_lock():
            self.proxy_id = self.proxy_id_glob.value
            self.proxy_id_glob.value += 1

        if self.proxy_id == 0:
            LOG.debug(f'Neon Proxy version: {self.neon_proxyVersion()}')
        LOG.debug(f"Worker id {self.proxy_id}")

    @property
    def _gas_price(self) -> MPGasPriceResult:
        now = math.ceil(time.time())
        if self._last_gas_price_time != now:
            gas_price = self._mempool_client.get_gas_price(get_req_id_from_log())
            if gas_price is not None:
                self._gas_price_value = gas_price

        if self._gas_price_value is None:
            raise EthereumError(message='Failed to calculate gas price. Try again later')
        return cast(MPGasPriceResult, self._gas_price_value)

    def neon_proxy_version(self) -> str:
        return self.neon_proxyVersion()

    def neon_cli_version(self) -> str:
        return self.neon_cliVersion()

    def neon_evm_version(self) -> str:
        return self.neon_evmVersion()

    @staticmethod
    def neon_proxyVersion() -> str:
        return 'Neon-proxy/v' + NEON_PROXY_PKG_VERSION + '-' + NEON_PROXY_REVISION

    @staticmethod
    def neon_evmVersion() -> str:
        return 'Neon/v' + ElfParams().neon_evm_version + '-' + ElfParams().neon_evm_revision

    def neon_cliVersion(self) -> str:
        return self._core_api_client.version()

    def neon_solanaVersion(self) -> str:
        return 'Solana/v' + self._solana.get_solana_version()

    def neon_versions(self) -> Dict[str, str]:
        return {
            'proxy': self.neon_proxyVersion(),
            'evm': self.neon_evmVersion(),
            'cli': self.neon_cliVersion(),
            'solana': self.neon_solanaVersion()
        }

    def web3_clientVersion(self) -> str:
        return self.neon_evmVersion()

    @staticmethod
    def eth_chainId() -> str:
        return hex(ElfParams().chain_id)

    @staticmethod
    def net_version() -> str:
        return str(ElfParams().chain_id)

    def eth_gasPrice(self) -> str:
        return hex(self._gas_price.suggested_gas_price)

    def neon_gasPrice(self, param: Dict[str, Any]) -> str:
        account = param.get('from', None)
        if account is None:
            return self._format_gas_price(self._gas_price.suggested_gas_price)

        account = self._normalize_address(account, 'from-address').lower()

        state_tx_cnt = self._core_api_client.get_state_tx_cnt(account)
        tx_nonce = param.get('nonce', None)
        if tx_nonce is not None:
            tx_nonce = self._normalize_hex(tx_nonce, 'nonce')
        if tx_nonce is None:
            tx_nonce = state_tx_cnt
        else:
            NonceTooLowError.raise_if_error(account, tx_nonce, state_tx_cnt)

        tx_gas = param.get('gas', 0)
        tx_gas = self._normalize_hex(tx_gas, 'gas')

        if self._has_gas_less_tx_permit(account, tx_nonce, tx_gas):
            return self._format_gas_price(0)

        return self._format_gas_price(self._gas_price.suggested_gas_price)

    def _format_gas_price(self, gas_price: int) -> Union[str, Dict[str, str]]:
        gas_price_info = self._gas_price
        return dict(
            gas_price=hex(gas_price),
            suggested_gas_price=hex(gas_price_info.suggested_gas_price),
            is_const_gas_price=gas_price_info.is_const_gas_price,
            min_acceptable_gas_price=hex(gas_price_info.min_acceptable_gas_price),
            min_executable_gas_price=hex(gas_price_info.min_executable_gas_price),
            min_wo_chainid_acceptable_gas_price=hex(gas_price_info.min_wo_chainid_acceptable_gas_price),
            allow_underpriced_tx_wo_chainid=gas_price_info.allow_underpriced_tx_wo_chainid,
            sol_price_usd=hex(gas_price_info.sol_price_usd),
            neon_price_usd=hex(gas_price_info.neon_price_usd),
            operator_fee=hex(gas_price_info.operator_fee),
            gas_price_slippage=hex(gas_price_info.gas_price_slippage)
        )

    @staticmethod
    def _normalize_hex(value: Union[str, int], name: str) -> int:
        try:
            if isinstance(value, int):
                return value
            elif not isinstance(value, str):
                raise RuntimeError('bad type')

            value = value.lower()
            if not value.startswith('0x'):
                raise RuntimeError('bad hex')

            return int(value[2:], 16)
        except (Exception,):
            raise InvalidParamError(f'invalid {name}: value')

    def _has_gas_less_tx_permit(self, account: str, tx_nonce: int, tx_gas_limit: int) -> bool:
        if self._config.gas_less_tx_max_nonce < tx_nonce:
            return False
        if self._config.gas_less_tx_max_gas < tx_gas_limit:
            return False

        return self._gas_tank.has_gas_less_tx_permit(account)

    def eth_estimateGas(self, param: Dict[str, Any]) -> str:
        if not isinstance(param, dict):
            raise InvalidParamError('invalid param')
        if 'from' in param:
            param['from'] = self._normalize_address(param['from'], 'from-address')
        if 'to' in param:
            param['to'] = self._normalize_address(param['to'], 'to-address')

        try:
            calculator = GasEstimate(self._core_api_client, param)
            calculator.execute()
            return hex(calculator.estimate())

        except EthereumError:
            raise
        except BaseException as exc:
            LOG.debug(f"Exception on eth_estimateGas: {str(exc)}")
            raise

    def __repr__(self):
        return str(self.__dict__)

    def _should_return_starting_block(self, tag: Union[str, int]) -> bool:
        return (tag == '0x0' or str(tag) == '0') and self._config.use_earliest_block_if_0_passed

    def _process_str_block_tag(self, tag: str) -> SolBlockInfo:
        assert isinstance(tag, str)

        tag = tag.lower().strip()
        if tag.startswith('0x'):
            return self._process_int_block_tag(tag)

        eth_commit = EthCommit.to_type(tag)
        sol_commit = SolCommit.from_ethereum(eth_commit)
        if sol_commit == SolCommit.Processed:
            latest_block = self._db.latest_block
            return SolBlockInfo(
                block_slot=latest_block.block_slot + 1,
                sol_commit=sol_commit,
                block_time=latest_block.block_time,
                parent_block_hash=latest_block.block_hash,
                parent_block_slot=latest_block.block_slot
            )
        elif sol_commit == SolCommit.Confirmed:
            return self._db.latest_block
        elif sol_commit in {SolCommit.Finalized, SolCommit.Safe}:
            return self._db.finalized_block
        elif sol_commit == SolCommit.Earliest:
            return self._db.earliest_block
        assert False, 'Bad commit level'

    def _process_int_block_tag(self, tag: Union[int, str]) -> SolBlockInfo:
        if isinstance(tag, str):
            tag = tag.lower().strip()
            assert tag.startswith('0x')
            tag = int(tag, 16)

        assert isinstance(tag, int)
        assert tag >= 0
        if tag == 0:
            return self._db.earliest_block

        return self._db.get_block_by_slot(tag)

    def _process_dict_block_tag(self, tag: Dict[str, Any]) -> SolBlockInfo:
        if 'blockHash' not in tag:
            return self._process_int_block_tag(tag['blockNumber'])

        assert 'blockNumber' not in tag
        tag = tag['blockHash']
        block = self._get_block_by_hash(tag)
        if block.is_empty():
            raise InvalidParamError(message=f'header for block hash {tag} not found')
        return block

    def _process_block_tag(self, tag: Union[str, int, dict]) -> SolBlockInfo:
        try:
            if isinstance(tag, str):
                return self._process_str_block_tag(tag)
            elif isinstance(tag, int):
                return self._process_int_block_tag(tag)
            elif isinstance(tag, dict):
                return self._process_dict_block_tag(tag)

            assert False, 'Wrong type'
        except (BaseException,):
            raise InvalidParamError(message=f'failed to parse block tag: {tag}')

    @staticmethod
    def _normalize_tx_id(tag: str) -> str:
        if not isinstance(tag, str):
            raise InvalidParamError(message='bad transaction-id format')

        try:
            tag = tag.lower().strip()
            assert len(tag) == 66
            assert tag[:2] == '0x'

            int(tag[2:], 16)
            return tag
        except (Exception,):
            raise InvalidParamError(message='transaction-id is not hex')

    @staticmethod
    def _normalize_address(raw_address: str, address_type='address') -> str:
        try:
            address = raw_address.strip().lower()
            assert address[:2] == '0x'
            address = address[2:]

            bin_address = bytes.fromhex(address)
            assert len(bin_address) == 20

            return eth_utils.to_checksum_address(address)
        except (Exception,):
            raise InvalidParamError(message=f'bad {address_type}: {raw_address}')

    def _get_full_block_by_number(self, tag: Union[str, int]) -> SolBlockInfo:
        block = self._process_block_tag(tag)
        if block.is_empty():
            LOG.debug(f'Not found block by slot {block.block_slot}')

        return block

    def eth_blockNumber(self) -> str:
        slot = self._db.latest_slot
        return hex(slot)

    def eth_getBalance(self, account: str, tag: Union[int, str, dict]) -> str:
        """account - address to check for balance.
           tag - integer block number, or the string "finalized", "safe", "latest", "earliest" or "pending"
        """

        block = self._process_block_tag(tag)
        account = self._normalize_address(account)

        try:
            neon_account_info = self._core_api_client.get_neon_account_info(account, block)
            if (neon_account_info is None) or (neon_account_info.balance == 0):
                return self._get_zero_balance(account, neon_account_info)

            return hex(neon_account_info.balance)
        except (Exception,):
            # LOG.debug(f"eth_getBalance: Can't get account info: {err}")
            return hex(0)

    def _get_zero_balance(self, account: str, neon_account_info: Optional[NeonAccountInfo]) -> str:
        nonce = neon_account_info.tx_count if neon_account_info is not None else 0
        if self._has_gas_less_tx_permit(account.lower(), nonce, 0):
            return hex(1)
        return hex(0)

    @staticmethod
    def _normalize_topic(raw_topic: Any) -> str:
        try:
            assert isinstance(raw_topic, str)

            topic = raw_topic.strip().lower()
            assert topic[:2] == '0x'
            topic = topic[2:]

            bin_topic = bytes.fromhex(topic)
            assert len(bin_topic) == 32

            return '0x' + bin_topic.hex().lower()
        except (Exception,):
            raise InvalidParamError(message=f'bad topic {raw_topic}')

    def _get_log_list(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        from_block: Optional[int] = None
        to_block: Optional[int] = None
        address_list: List[str] = list()
        topic_list: List[List[str]] = list()

        if obj.get('fromBlock', 0) not in {0, '0x0', EthCommit.Earliest}:
            from_block = self._process_block_tag(obj['fromBlock']).block_slot
        if obj.get('toBlock', 'latest') not in {EthCommit.Latest, EthCommit.Pending}:
            to_block = self._process_block_tag(obj['toBlock']).block_slot

        if obj.get('blockHash', None) is not None:
            if ('fromBlock' in obj) or ('toBlock' in obj):
                raise InvalidParamError(
                    message='invalid filter: if blockHash is supplied fromBlock and toBlock must not be"',
                    code=-32600
                )

            block_hash = obj['blockHash']
            block = self._get_block_by_hash(block_hash)
            if block.is_empty():
                raise InvalidParamError(message=f'block hash {block_hash} does not exist')

            from_block = block.block_slot
            to_block = block.block_slot

        if obj.get('address', None) is not None:
            raw_address_list = obj['address']
            if isinstance(raw_address_list, str):
                address_list = [self._normalize_address(raw_address_list).lower()]
            elif isinstance(raw_address_list, list):
                for raw_address in raw_address_list:
                    address_list.append(self._normalize_address(raw_address).lower())
            else:
                raise InvalidParamError(message=f'bad address {raw_address_list}')

        if 'topics' in obj:
            raw_topic_list = obj['topics']
            if raw_topic_list is None:
                raw_topic_list = []

            if not isinstance(raw_topic_list, list):
                raise InvalidParamError(message=f'bad topics {raw_topic_list}')

            for raw_topic in raw_topic_list:
                if isinstance(raw_topic, list):
                    item_list = [self._normalize_topic(raw_item) for raw_item in raw_topic if raw_item is not None]
                    topic_list.append(item_list)
                elif raw_topic is None:
                    topic_list.append(list())
                else:
                    topic_list.append([self._normalize_topic(raw_topic)])

        return self._db.get_log_list(from_block, to_block, address_list, topic_list)

    def _filter_log_list(self, log_list: List[Dict[str, Any]], full: bool) -> List[Dict[str, Any]]:
        filtered_log_list: List[Dict[str, Any]] = list()

        for log_rec in log_list:
            if (not full) and log_rec.get('neonIsHidden', False):
                continue

            new_log_rec: Dict[str, Any] = {
                'removed': False,
            }

            for key, value in log_rec.items():
                if (key == 'data') and (not len(value)):
                    new_log_rec[key] = '0x'
                elif full and (key == 'neonEventType'):
                    new_log_rec[key] = self._decode_event_type(value)
                elif full or (key[:4] != 'neon'):
                    new_log_rec[key] = value

            filtered_log_list.append(new_log_rec)
        return filtered_log_list

    @staticmethod
    def _decode_event_type(event_type: int) -> Union[str, int]:
        event_type_dict: Dict[int, str] = {
            1: 'LOG',
            101: 'ENTER CALL',
            102: 'ENTER CALL CODE',
            103: 'ENTER STATICCALL',
            104: 'ENTER DELEGATECALL',
            105: 'ENTER CREATE',
            106: 'ENTER CREATE2',
            201: 'EXIT STOP',
            202: 'EXIT RETURN',
            203: 'EXIT SELFDESTRUCT',
            204: 'EXIT REVERT',
            300: 'RETURN',
            301: 'CANCEL'
        }

        value = event_type_dict.get(event_type, None)
        if value is None:
            return event_type
        return value

    def eth_getLogs(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        log_list = self._get_log_list(obj)
        return self._filter_log_list(log_list, False)

    def neon_getLogs(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        log_list = self._get_log_list(obj)
        return self._filter_log_list(log_list, True)

    def _get_block_by_slot(self, block: SolBlockInfo, full: bool, skip_transaction: bool) -> Optional[dict]:
        if block.is_empty():
            return None

        sig_list = list()
        total_gas_used = 0
        if skip_transaction:
            tx_list = list()
        else:
            tx_list = self._db.get_tx_list_by_block_slot(block.block_slot)

        for tx in tx_list:
            total_gas_used = max(tx.neon_tx_res.sum_gas_used, total_gas_used)

            if full:
                receipt = self._get_transaction(tx)
                sig_list.append(receipt)
            else:
                sig_list.append(tx.neon_tx.sig)

        # by default - maximum BPF cycles in Solana block
        max_gas_used = max(48_000_000_000_000, total_gas_used)
        empty_root = '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421'
        root = empty_root if len(tx_list) == 0 else '0x' + '0' * 63 + '1'

        result = {
            "logsBloom": '0x' + '0' * 512,
            "transactionsRoot": root,
            "receiptsRoot": root,
            "stateRoot": '0x' + '0' * 63 + '1',


            "uncles": [],
            "sha3Uncles": '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347',

            "difficulty": '0x0',
            "totalDifficulty": '0x0',
            "extraData": '0x',
            "miner": '0x' + '0' * 40,
            "nonce": '0x0000000000000000',
            "mixHash": '0x' + '0' * 63 + '1',
            "size": '0x' + '1',

            "gasLimit": hex(max_gas_used),
            "gasUsed": hex(total_gas_used),
            "hash": block.block_hash,
            "number": hex(block.block_slot),
            "parentHash": block.parent_block_hash,
            "timestamp": hex(block.block_time),
            "transactions": sig_list,
        }
        return result

    def eth_getStorageAt(self, contract: str, position: Union[int, str], tag: Union[int, str, dict]) -> str:
        """
        Retrieves storage data by given position
        Currently supports only 'latest' block
        """

        block = self._process_block_tag(tag)
        contract = self._normalize_address(contract)
        position = hex(self._normalize_hex(position, 'position'))

        try:
            return self._core_api_client.get_storage_at(contract, position, block)
        except (BaseException,):
            # LOG.error(f'eth_getStorageAt: Neon-cli failed to execute: {str(err)}')
            return '0x' + 64 * '0'

    def _get_block_by_hash(self, block_hash: str) -> SolBlockInfo:
        try:
            block_hash = block_hash.strip().lower()
            assert block_hash[:2] == '0x'

            bin_block_hash = bytes.fromhex(block_hash[2:])
            assert len(bin_block_hash) == 32
        except (Exception,):
            raise InvalidParamError(message=f'bad block hash {block_hash}')

        block = self._db.get_block_by_hash(block_hash)
        if block.is_empty():
            LOG.debug("Not found block by hash %s", block_hash)

        return block

    def eth_getBlockByHash(self, block_hash: str, full: bool) -> Optional[dict]:
        """Returns information about a block by hash.
            block_hash - Hash of a block.
            full - If true it returns the full transaction objects, if false only the hashes of the transactions.
        """
        block = self._get_block_by_hash(block_hash)
        if block.is_empty():
            return None
        ret = self._get_block_by_slot(block, full, False)
        return ret

    def eth_getBlockByNumber(self, tag: Union[int, str], full: bool) -> Optional[dict]:
        """Returns information about a block by block number.
            tag  - integer of a block number, or the string "finalized", "safe", "earliest", "latest" or "pending",
                   as in the default block parameter.
            full - If true it returns the full transaction objects, if false only the hashes of the transactions.
        """
        is_pending = tag == EthCommit.Pending
        block = self._process_block_tag(tag)
        ret = self._get_block_by_slot(block, full, is_pending)
        if is_pending:
            ret['miner'] = None
            ret['hash'] = None
            ret['nonce'] = None
        return ret

    def eth_call(self, obj: dict, tag: Union[int, str, dict]) -> str:
        """Executes a new message call immediately without creating a transaction on the blockchain.
           Parameters
            obj - The transaction call object
                from: DATA, 20 Bytes - (optional) The address the transaction is sent from.
                to: DATA, 20 Bytes   - The address the transaction is directed to.
                value: QUANTITY      - (optional) Integer of the value sent with this transaction
                data: DATA           - (optional) Hash of the method signature and encoded parameters.
                                       For details see Ethereum Contract ABI in the Solidity documentation
            tag                      - integer block number, or the string "finalized", "safe", "latest",
                                       "earliest" or "pending", see the default block parameter
        """
        block = self._process_block_tag(tag)
        if not isinstance(obj, dict):
            raise InvalidParamError(message='invalid object type')

        if not obj['data']:
            raise InvalidParamError(message="missing data")

        try:
            sender = obj.get('from')
            contract = obj.get('to')
            data = obj.get('data')
            value = obj.get('value')

            retry_idx = 0
            retry_on_fail = self._config.retry_on_fail
            while True:
                try:
                    emulator_result = self._core_api_client.emulate(contract, sender, data, value, block, True)
                    return '0x' + emulator_result.result

                except RescheduleError:
                    retry_idx += 1
                    if retry_idx < retry_on_fail:
                        continue
                    raise

        except EthereumError:
            raise

        except Exception as err:
            LOG.debug(f'eth_call Exception {err}.')
            raise

    def eth_getTransactionCount(self, account: str, tag: Union[str, int, dict]) -> str:
        block = self._process_block_tag(tag) if tag != 'mempool' else None
        account = self._normalize_address(account).lower()

        try:
            LOG.debug(f'Get transaction count. Account: {account}, tag: {tag}')

            mempool_tx_nonce: Optional[int] = None
            req_id = get_req_id_from_log()

            if tag == 'mempool':
                mempool_tx_nonce = self._mempool_client.get_mempool_tx_nonce(req_id=req_id, sender=account)
                LOG.debug(f'Mempool tx count for: {account} - is: {mempool_tx_nonce}')

            elif (block is not None) and (block.sol_commit == SolCommit.Processed):
                mempool_tx_nonce = self._mempool_client.get_pending_tx_nonce(req_id=req_id, sender=account)
                LOG.debug(f'Pending tx count for: {account} - is: {mempool_tx_nonce}')

            if mempool_tx_nonce is None:
                mempool_tx_nonce = 0

            tx_cnt = self._core_api_client.get_state_tx_cnt(account, block)
            tx_cnt = max(tx_cnt, mempool_tx_nonce)

            return hex(tx_cnt)
        except (Exception,):
            # LOG.debug(f"eth_getTransactionCount: Can't get account info: {err}")
            return hex(0)

    def _fill_transaction_receipt_answer(self, tx: NeonTxReceiptInfo, full: bool) -> dict:
        log_list = self._filter_log_list(tx.neon_tx_res.log_list, False)

        receipt = {
            "transactionHash": tx.neon_tx.sig,
            "transactionIndex": hex(tx.neon_tx_res.tx_idx),
            "type": hex(tx.neon_tx.tx_type),
            "blockHash": tx.neon_tx_res.block_hash,
            "blockNumber": hex(tx.neon_tx_res.block_slot),
            "from": tx.neon_tx.addr,
            "to": tx.neon_tx.to_addr,
            "gasUsed": hex(tx.neon_tx_res.gas_used),
            "cumulativeGasUsed": hex(tx.neon_tx_res.sum_gas_used),
            "contractAddress": tx.neon_tx.contract,
            "logs": log_list,
            "status": hex(tx.neon_tx_res.status),
            "logsBloom": "0x" + '0' * 512
        }

        if full:
            self._fill_sol_tx_info_list(tx, receipt)
            receipt.update({
                'neonIsCompleted': tx.neon_tx_res.is_completed,
                'neonIsCanceled': tx.neon_tx_res.is_canceled
            })

        return receipt

    def _fill_sol_tx_info_list(self, tx: NeonTxReceiptInfo, receipt: Dict[str, Any]) -> None:
        result_tx_list: List[Dict[str, Any]] = list()
        result_cost_list: List[Dict[str, Union[str, int]]] = list()

        receipt['solanaTransactions'] = result_tx_list
        receipt['neonCosts'] = result_cost_list

        sol_neon_ix_list: List[SolNeonIxReceiptInfo] = self._db.get_sol_ix_info_list_by_neon_sig(tx.neon_tx.sig)
        if not len(sol_neon_ix_list):
            LOG.warning(f'Cannot find Solana txs for the Neon tx {tx.neon_tx.sig}')
            return

        sol_alt_ix_list: List[SolAltIxInfo] = self._db.get_sol_alt_tx_list_by_neon_sig(tx.neon_tx.sig)
        full_log_dict: Dict[str, List[Dict[str, Any]]] = self._get_full_log_dict(tx)

        sol_sig = ''
        op_cost = OpCostInfo()
        result_ix_list: List[Dict[str, Any]] = list()
        result_cost_dict: Dict[str, OpCostInfo] = dict()

        def _fill_sol_tx(ix: Union[SolNeonIxReceiptInfo, SolAltIxInfo]):
            tx_cost = ix.sol_tx_cost
            new_op_cost = result_cost_dict.setdefault(tx_cost.operator, OpCostInfo())
            new_op_cost.sol_spent += tx_cost.sol_spent

            new_ix_list: List[Dict[str, Any]] = list()
            result_tx_list.append({
                'solanaTransactionHash': ix.sol_sig,
                'solanaTransactionIsSuccess': ix.is_success,
                'solanaBlockNumber': hex(ix.block_slot),
                'solanaLamportSpent': hex(tx_cost.sol_spent),
                'solanaOperator': tx_cost.operator,
                'solanaInstructions': new_ix_list,
            })
            return new_ix_list, new_op_cost

        for neon_ix in sol_neon_ix_list:
            if neon_ix.sol_sig != sol_sig:
                sol_sig = neon_ix.sol_sig
                result_ix_list, op_cost = _fill_sol_tx(neon_ix)

            neon_income = neon_ix.neon_gas_used * tx.neon_tx.gas_price
            op_cost.neon_income += neon_income
            log_list_key = ':'.join([sol_sig, str(neon_ix.idx), str(neon_ix.inner_idx)])

            result_ix_list.append({
                'solanaProgram': 'NeonEVM',
                'solanaInstructionIndex': hex(neon_ix.idx),
                'solanaInnerInstructionIndex': hex(neon_ix.inner_idx) if neon_ix.inner_idx is not None else None,
                'svmHeapSizeLimit': hex(neon_ix.max_heap_size),
                'svmHeapSizeUsed': hex(neon_ix.used_heap_size),
                'svmCyclesLimit': hex(neon_ix.max_bpf_cycle_cnt),
                'svmCyclesUsed': hex(neon_ix.used_bpf_cycle_cnt),
                'neonInstructionCode': hex(neon_ix.ix_code),
                'neonInstructionName': EvmIxCodeName().get(neon_ix.ix_code),
                'neonStepLimit': hex(neon_ix.neon_step_cnt) if neon_ix.neon_step_cnt > 0 else None,
                'neonAlanIncome': hex(neon_income),
                'neonGasUsed': hex(neon_ix.neon_gas_used),
                'neonTotalGasUsed': hex(neon_ix.neon_total_gas_used),
                'neonLogs': full_log_dict.get(log_list_key, None),
            })

        sol_sig = ''
        for alt_ix in sol_alt_ix_list:
            if alt_ix.sol_sig != sol_sig:
                sol_sig = alt_ix.sol_sig
                result_ix_list, op_cost = _fill_sol_tx(alt_ix)

            result_ix_list.append({
                'solanaProgram': 'AddressLookupTable',
                'solanaInstructionIndex': hex(alt_ix.idx),
                'solanaInnerInstructionIndex': hex(alt_ix.inner_idx) if alt_ix.inner_idx is not None else None,
                'altInstructionCode': hex(alt_ix.ix_code),
                'altInstructionName': AltIxCodeName().get(alt_ix.ix_code),
                'altAddress': alt_ix.alt_address,
            })

        result_cost_list.extend([{
                'solanaOperator': op,
                'solanaLamportSpent': hex(cost.sol_spent),
                'neonAlanIncome': hex(cost.neon_income)
            }
            for op, cost in result_cost_dict.items()
        ])

    def _get_full_log_dict(self, tx: NeonTxReceiptInfo) -> Dict[str, List[Dict[str, Any]]]:
        remove_neon_key_list = ['neonSolHash', 'neonIxIdx', 'neonInnerIxIdx']
        remove_eth_key_list = ['removed', 'transactionHash', 'transactionIndex', 'blockHash', 'blockNumber']

        full_log_list: List[Dict[str, Any]] = self._filter_log_list(tx.neon_tx_res.log_list, True)
        full_log_dict: Dict[str, List[Dict[str, Any]]] = dict()
        for log_rec in full_log_list:
            log_list_key = ':'.join([log_rec['neonSolHash'], str(log_rec['neonIxIdx']), str(log_rec['neonInnerIxIdx'])])
            for key in remove_neon_key_list:
                log_rec.pop(key, None)
            if 'transactionLogIndex' not in log_rec:
                for key in remove_eth_key_list:
                    log_rec.pop(key, None)

            full_log_dict.setdefault(log_list_key, list()).append(log_rec)
        return full_log_dict

    def _get_transaction_receipt(self, neon_tx_sig: str) -> Optional[NeonTxReceiptInfo]:
        neon_sig = self._normalize_tx_id(neon_tx_sig)

        neon_tx_or_error = self._mempool_client.get_pending_tx_by_hash(get_req_id_from_log(), neon_tx_sig)
        if isinstance(neon_tx_or_error, EthereumError):
            raise neon_tx_or_error
        return self._db.get_tx_by_neon_sig(neon_sig)

    def eth_getTransactionReceipt(self, neon_tx_sig: str) -> Optional[dict]:
        tx = self._get_transaction_receipt(neon_tx_sig)
        if tx is None:
            return None
        return self._fill_transaction_receipt_answer(tx, False)

    def neon_getTransactionReceipt(self, neon_tx_sig: str) -> Optional[dict]:
        tx = self._get_transaction_receipt(neon_tx_sig)
        if tx is None:
            return None
        return self._fill_transaction_receipt_answer(tx, True)

    @staticmethod
    def _get_transaction(tx: NeonTxReceiptInfo) -> Dict[str, Any]:
        t = tx.neon_tx
        r = tx.neon_tx_res

        hex_block_number = None
        if r.block_slot is not None:
            hex_block_number = hex(r.block_slot)

        hex_tx_idx = None
        if r.tx_idx is not None:
            hex_tx_idx = hex(r.tx_idx)

        result = {
            "blockHash": r.block_hash,
            "blockNumber": hex_block_number,
            "hash": t.sig,
            "transactionIndex": hex_tx_idx,
            "type": hex(t.tx_type),
            "from": t.addr,
            "nonce": hex(t.nonce),
            "gasPrice": hex(t.gas_price),
            "gas": hex(t.gas_limit),
            "to": t.to_addr,
            "value": hex(t.value),
            "input": t.calldata,
            "v": hex(t.v),
            "r": hex(t.r),
            "s": hex(t.s),
        }

        return result

    def eth_getTransactionByHash(self, neon_tx_sig: str) -> Optional[dict]:
        neon_sig = self._normalize_tx_id(neon_tx_sig)

        neon_tx_receipt: NeonTxReceiptInfo = self._db.get_tx_by_neon_sig(neon_sig)
        if neon_tx_receipt is None:
            neon_tx: Union[NeonTxInfo, EthereumError, None] = self._mempool_client.get_pending_tx_by_hash(
                get_req_id_from_log(), neon_sig
            )
            if neon_tx is None:
                LOG.debug("Not found receipt")
                return None
            elif isinstance(neon_tx, EthereumError):
                raise neon_tx

            neon_tx_receipt = NeonTxReceiptInfo(neon_tx, NeonTxResultInfo())
        return self._get_transaction(neon_tx_receipt)

    def neon_getTransactionBySenderNonce(self, address: str, nonce: Union[int, str]) -> Optional[Dict[str, Any]]:
        sender_addr = self._normalize_address(address).lower()
        if isinstance(nonce, str):
            nonce = nonce.lower()
            if nonce[:2] == '0x':
                tx_nonce = int(nonce, 16)
            else:
                tx_nonce = int(nonce, 10)
        else:
            tx_nonce = nonce

        neon_tx_receipt: NeonTxReceiptInfo = self._db.get_tx_by_sender_nonce(sender_addr, tx_nonce)
        if neon_tx_receipt is None:
            neon_tx: MPNeonTxResult = self._mempool_client.get_pending_tx_by_sender_nonce(
                get_req_id_from_log(), sender_addr, tx_nonce
            )
            if neon_tx is None:
                LOG.debug("Not found receipt")
                return None
            elif isinstance(neon_tx, EthereumError):
                raise neon_tx

        return self._get_transaction(neon_tx_receipt)

    def eth_getCode(self, account: str, tag: Union[str, int, dict]) -> str:
        block = self._process_block_tag(tag)
        account = self._normalize_address(account)

        try:
            account_info = self._core_api_client.get_neon_account_info(account, block)
            if (not account_info) or (not account_info.code):
                return '0x'

            return account_info.code
        except (Exception,):
            return '0x'

    def eth_sendRawTransaction(self, raw_tx: str) -> str:
        neon_tx: NeonTx = self._decode_neon_raw_tx(raw_tx)
        # validate that tx was executed 2 times (second in the except section)
        if self._is_neon_tx_exist(neon_tx):
            return neon_tx.hex_tx_sig

        try:
            neon_tx_exec_cfg: NeonTxExecCfg = self._get_neon_tx_exec_cfg(neon_tx)

            result: MPTxSendResult = self._mempool_client.send_raw_transaction(
                req_id=get_req_id_from_log(), neon_tx=neon_tx, neon_tx_exec_cfg=neon_tx_exec_cfg
            )

            if result.code in (MPTxSendResultCode.Success, MPTxSendResultCode.AlreadyKnown):
                return neon_tx.hex_tx_sig
            elif result.code == MPTxSendResultCode.Underprice:
                raise EthereumError(message='replacement transaction underpriced')
            elif result.code == MPTxSendResultCode.NonceTooLow:
                NonceTooLowError.raise_error(neon_tx.hex_sender, neon_tx.nonce, result.state_tx_cnt)
            else:
                raise EthereumError(message='unknown error')
        except BaseException as exc:
            # revalidate that tx was executed
            if self._is_neon_tx_exist(neon_tx):
                return neon_tx.hex_tx_sig
            elif isinstance(exc, NonceTooLowError):
                self._validate_old_nonce(neon_tx)
                return neon_tx.hex_tx_sig

            if not isinstance(exc, EthereumError):
                LOG.error('Failed to process eth_sendRawTransaction', exc_info=exc)
            raise

    @staticmethod
    def _decode_neon_raw_tx(raw_tx: str) -> NeonTx:
        try:
            neon_tx = NeonTx.from_string(bytearray.fromhex(raw_tx[2:]))
        except (Exception,):
            raise InvalidParamError(message='wrong transaction format')

        def _readable_tx(tx: NeonTx) -> Dict[str, Any]:
            fmt_tx = dict()
            for k, v in tx.as_dict().items():
                if isinstance(v, bytearray) or isinstance(v, bytes):
                    fmt_tx[k] = v.hex()
                else:
                    fmt_tx[k] = v

            fmt_tx['sender'] = tx.sender.hex()
            return fmt_tx

        LOG.debug(f'sendRawTransaction {neon_tx.hex_tx_sig}: {_readable_tx(neon_tx)}')
        return neon_tx

    def _is_neon_tx_exist(self, neon_tx: NeonTx) -> bool:
        neon_tx_receipt = self._db.get_tx_by_neon_sig(neon_tx.hex_tx_sig)
        if neon_tx_receipt is not None:
            if neon_tx_receipt.neon_tx_res.block_slot <= self._db.finalized_slot:
                raise EthereumError(message='already known')
            return True

        neon_tx_or_error = self._mempool_client.get_pending_tx_by_hash(get_req_id_from_log(), neon_tx.hex_tx_sig)
        return neon_tx_or_error is not None

    def _validate_old_nonce(self, neon_tx: NeonTx) -> None:
        # There are several Proxies in the network with independent mempools,
        #   the network can switch between branches
        #   so the Proxy returns the good result if Neon Tx wasn't finalized
        tx_sender = neon_tx.hex_sender
        tx_nonce = int(neon_tx.nonce)
        block = self._process_block_tag(EthCommit.Finalized)
        state_tx_cnt = self._core_api_client.get_state_tx_cnt(tx_sender, block)
        NonceTooLowError.raise_if_error(tx_sender, tx_nonce, state_tx_cnt)

    def _get_neon_tx_exec_cfg(self, neon_tx: NeonTx) -> NeonTxExecCfg:
        gas_less_permit = False
        if neon_tx.gasPrice == 0:
            gas_less_permit = self._has_gas_less_tx_permit(neon_tx.hex_sender, neon_tx.nonce, neon_tx.gasLimit)

        min_gas_price = self._gas_price.min_executable_gas_price
        validator = NeonTxValidator(self._config, self._core_api_client, neon_tx, gas_less_permit, min_gas_price)
        neon_tx_exec_cfg = validator.validate()

        return neon_tx_exec_cfg

    def _get_transaction_by_index(self, block: SolBlockInfo, tx_idx: Union[str, int]) -> Optional[Dict[str, Any]]:
        try:
            if isinstance(tx_idx, str):
                tx_idx = int(tx_idx, 16)
            assert tx_idx >= 0
        except (Exception,):
            raise EthereumError(message=f'invalid transaction index {tx_idx}')

        if block.is_empty():
            block = self._db.get_block_by_slot(block.block_slot)
            if block.is_empty():
                LOG.debug(f"Not found block by slot {block.block_slot}")
                return None

        neon_tx_receipt = self._db.get_tx_by_block_slot_tx_idx(block.block_slot, tx_idx)
        if neon_tx_receipt is None:
            LOG.debug("Not found receipt")
            return None
        return self._get_transaction(neon_tx_receipt)

    def eth_getTransactionByBlockNumberAndIndex(self, tag: Union[str, int, dict], idx: int) -> Optional[Dict[str, Any]]:
        block = self._process_block_tag(tag)
        return self._get_transaction_by_index(block, idx)

    def eth_getTransactionByBlockHashAndIndex(self, block_hash: str, tx_idx: int) -> Optional[Dict[str, Any]]:
        block = self._get_block_by_hash(block_hash)
        if block.is_empty():
            return None
        return self._get_transaction_by_index(block, tx_idx)

    def eth_getBlockTransactionCountByHash(self, block_hash: str) -> str:
        block = self._get_block_by_hash(block_hash)
        if block.is_empty():
            return hex(0)
        if block.is_empty():
            block = self._db.get_block_by_slot(block.block_slot)
            if block.is_empty():
                LOG.debug(f"Not found block by slot {block.block_slot}")
                return hex(0)

        tx_list = self._db.get_tx_list_by_block_slot(block.block_slot)
        return hex(len(tx_list))

    def eth_getBlockTransactionCountByNumber(self, tag: str) -> str:
        block = self._get_full_block_by_number(tag)
        if block.is_empty():
            return hex(0)

        tx_list = self._db.get_tx_list_by_block_slot(block.block_slot)
        return hex(len(tx_list))

    @staticmethod
    def eth_accounts() -> [str]:
        storage = KeyStorage()
        account_list = storage.get_list()
        return [str(a) for a in account_list]

    def eth_sign(self, address: str, data: str) -> str:
        address = self._normalize_address(address)
        try:
            data = bytes.fromhex(data[2:])
        except (Exception,):
            raise InvalidParamError(message='data is not hex string')

        account = KeyStorage().get_key(address)
        if not account:
            raise EthereumError(message='unknown account')

        message = str.encode(f'\x19Ethereum Signed Message:\n{len(data)}') + data
        return str(account.private.sign_msg(message))

    def eth_signTransaction(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        if 'from' not in tx:
            raise InvalidParamError(message='no sender in transaction')

        sender = tx['from']
        del tx['from']
        sender = self._normalize_address(sender, 'from-address')

        if 'to' in tx:
            tx['to'] = self._normalize_address(tx['to'], 'to-address')

        account = KeyStorage().get_key(sender)
        if not account:
            raise EthereumError(message='unknown account')

        if 'nonce' not in tx:
            tx['nonce'] = self.eth_getTransactionCount(sender, EthCommit.Pending)

        if 'chainId' not in tx:
            tx['chainId'] = hex(ElfParams().chain_id)

        try:
            signed_tx = NeonAccount().sign_transaction(tx, account.private)
            raw_tx = signed_tx.rawTransaction.hex()
            neon_tx = NeonTx.from_string(bytearray.fromhex(raw_tx[2:]))

            tx.update({
                'from': neon_tx.hex_sender,
                'to': neon_tx.hex_to_address,
                'hash': neon_tx.hex_tx_sig,
                'r': hex(neon_tx.r),
                's': hex(neon_tx.s),
                'v': hex(neon_tx.v)
            })

            return {
                'raw': raw_tx,
                'tx': tx
            }
        except BaseException as exc:
            LOG.error('Failed on sign transaction.', exc_info=exc)
            raise InvalidParamError(message='bad transaction')

    def eth_sendTransaction(self, tx: Dict[str, Any]) -> str:
        tx = self.eth_signTransaction(tx)
        return self.eth_sendRawTransaction(tx['raw'])

    @staticmethod
    def web3_sha3(data: str) -> str:
        try:
            data = bytes.fromhex(data[2:])
        except (Exception,):
            raise InvalidParamError(message='data is not hex string')

        return '0x' + keccak_256(data).hexdigest()

    @staticmethod
    def eth_mining() -> bool:
        return False

    @staticmethod
    def eth_hashrate() -> str:
        return hex(0)

    @staticmethod
    def eth_getWork() -> [str]:
        return ['', '', '', '']

    def eth_syncing(self) -> Union[bool, dict]:
        try:
            slots_behind = self._solana.get_slots_behind()
            latest_slot = self._db.latest_slot
            first_slot = self._db.earliest_slot

            LOG.debug(f'slots_behind: {slots_behind}, latest_slot: {latest_slot}, first_slot: {first_slot}')
            if (slots_behind == 0) or (slots_behind is None) or (latest_slot is None) or (first_slot is None):
                return False

            return {
                'startingBlock': first_slot,
                'currentBlock': latest_slot,
                'highestBlock': latest_slot + slots_behind
            }
        except (Exception,):
            return False

    def net_peerCount(self) -> str:
        cluster_node_list = self._solana.get_cluster_nodes()
        return hex(len(cluster_node_list))

    @staticmethod
    def net_listening() -> bool:
        return False

    @staticmethod
    def _mp_pool_tx(neon_tx_info: NeonTxInfo) -> Dict[str, Any]:
        return {
            'blockHash': '0x' + '0' * 64,
            'blockNumber': None,
            'transactionIndex': None,
            'from': neon_tx_info.addr,
            'gas': hex(neon_tx_info.gas_limit),
            'gasPrice': hex(neon_tx_info.gas_price),
            'hash': neon_tx_info.sig,
            'input': neon_tx_info.calldata,
            'nonce': hex(neon_tx_info.nonce),
            'to': neon_tx_info.to_addr,
            'value': hex(neon_tx_info.value)
        }

    def _mp_pool_queue(self, tx_list: List[NeonTxInfo]) -> Dict[str, Any]:
        sender_addr = ''
        sender_pool: Dict[int, Any] = dict()
        sender_pool_dict: Dict[str, Any] = dict()
        for tx in tx_list:
            if sender_addr != tx.addr and len(sender_addr):
                sender_pool_dict[sender_addr] = sender_pool
                sender_pool = dict()

            sender_addr = tx.addr
            sender_pool[tx.nonce] = self._mp_pool_tx(tx)

        if len(sender_addr):
            sender_pool_dict[sender_addr] = sender_pool

        return sender_pool_dict

    def txpool_content(self) -> Dict[str, Any]:
        result_dict: Dict[str, Any] = dict()

        req_id = get_req_id_from_log()
        content = self._mempool_client.get_content(req_id)

        result_dict['pending'] = self._mp_pool_queue(content.pending_list)
        result_dict['queued'] = self._mp_pool_queue(content.queued_list)
        return result_dict

    def neon_getSolanaTransactionByNeonTransaction(
        self, neon_tx_id: str,
        full: bool = False
    ) -> Union[List[str], List[Optional[Dict[str, Any]]]]:
        neon_sig = self._normalize_tx_id(neon_tx_id)
        alt_sig_list = self._db.get_alt_sig_list_by_neon_sig(neon_sig)
        sol_sig_list = self._db.get_sol_sig_list_by_neon_sig(neon_sig)

        sol_sig_list = alt_sig_list + sol_sig_list
        if not full:
            return sol_sig_list

        sol_tx_list = self._solana.get_tx_receipt_list(sol_sig_list, SolCommit.Confirmed)
        return sol_tx_list

    def neon_emulate(self, raw_signed_tx: str):
        """Executes emulator with given transaction"""
        LOG.debug(f'Call neon_emulate: {raw_signed_tx}')

        neon_tx = NeonTx.from_string(bytearray.fromhex(raw_signed_tx))
        emulator_result = self._core_api_client.emulate_neon_tx(neon_tx)
        return emulator_result.full_dict

    def neon_finalizedBlockNumber(self) -> str:
        slot = self._db.finalized_slot
        return hex(slot)

    def neon_earliestBlockNumber(self) -> str:
        slot = self._db.earliest_slot
        return hex(slot)

    @staticmethod
    def neon_getEvmParams() -> Dict[str, str]:
        """Returns map of Neon-EVM parameters"""
        elf_param_dict = ElfParams().elf_param_dict
        elf_param_dict['NEON_EVM_ID'] = EVM_PROGRAM_ID_STR
        return elf_param_dict

    def is_allowed_api(self, method_name: str) -> bool:
        for prefix in ('eth_', 'net_', 'web3_', 'neon_', 'txpool_'):
            if method_name.startswith(prefix):
                break
        else:
            return False

        if method_name == 'neon_proxyVersion':
            return True

        now = math.ceil(time.time())
        elf_params = ElfParams()
        if self._last_elf_params_time != now:
            result = self._mempool_client.get_elf_param_dict(get_req_id_from_log())
            if result is None:
                raise EthereumError(message='Failed to read Neon EVM params from Solana cluster. Try again later')
            elf_params.set_elf_param_dict(result.elf_param_dict, result.last_deployed_slot)

        always_allowed_method_set = {
            "eth_chainId",
            "neon_cliVersion",
            "neon_evmVersion",
            "neon_solanaVersion",
            "neon_versions",
            "neon_getEvmParams",
            "net_version",
            "web3_clientVersion"
        }

        if method_name in always_allowed_method_set:
            if elf_params.has_params():
                return True

        if not elf_params.is_evm_compatible(NEON_PROXY_PKG_VERSION):
            raise EthereumError(
                f'Neon Proxy {self.neon_proxyVersion()} is not compatible with '
                f'Neon EVM {self.web3_clientVersion()}'
            )

        if method_name == 'eth_sendRawTransaction':
            return self._config.enable_send_tx_api

        private_method_set = {
            "eth_accounts",
            "eth_sign",
            "eth_sendTransaction",
            "eth_signTransaction",
            "txpool_content"
        }

        if method_name in private_method_set:
            if (not self._config.enable_send_tx_api) or (not self._config.enable_private_api):
                return False

        return True
