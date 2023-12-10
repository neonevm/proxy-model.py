from __future__ import annotations

import logging
import math
import multiprocessing
import threading
import time
import base58

from dataclasses import dataclass
from typing import Optional, Union, Dict, Any, List, cast, NewType, Iterable

from eth_account import Account as NeonAccount
from sha3 import keccak_256

from .estimate import GasEstimate
from .transaction_validator import NeonTxValidator

from ..common_neon.address import NeonAddress
from ..common_neon.config import Config
from ..common_neon.constants import EVM_PROGRAM_ID_STR
from ..common_neon.data import NeonTxExecCfg
from ..common_neon.db.db_connect import DBConnection
from ..common_neon.errors import EthereumError, InvalidParamError, NonceTooLowError
from ..common_neon.eth_commit import EthCommit
from ..common_neon.evm_config import EVMConfig
from ..common_neon.keys_storage import KeyStorage
from ..common_neon.neon_instruction import EvmIxCodeName, AltIxCodeName
from ..common_neon.neon_tx_receipt_info import NeonTxReceiptInfo
from ..common_neon.neon_tx_result_info import NeonTxResultInfo
from ..common_neon.solana_block import SolBlockInfo
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_neon_tx_receipt import SolNeonIxReceiptInfo, SolAltIxInfo
from ..common_neon.solana_tx import SolCommit
from ..common_neon.utils import NeonTxInfo
from ..common_neon.utils.eth_proto import NeonTx
from ..common_neon.evm_log_decoder import NeonLogTxEvent
from ..common_neon.utils.utils import cached_property, u256big_to_hex, hex_to_bytes

from ..gas_tank.gas_less_accounts_db import GasLessAccountsDB

from ..indexer.indexer_db import IndexerDB

from ..mempool import (
    MemPoolClient, MP_SERVICE_ADDR,
    MPNeonTxResult, MPTxSendResult, MPTxSendResultCode, MPGasPriceResult, MPGasPriceTokenResult
)

from ..neon_core_api.neon_core_api_client import NeonCoreApiClient
from ..neon_core_api.neon_layouts import NeonAccountInfo


NEON_PROXY_PKG_VERSION = '1.7.0-dev'
NEON_PROXY_REVISION = 'NEON_PROXY_REVISION_TO_BE_REPLACED'
LOG = logging.getLogger(__name__)


@dataclass
class OpCostInfo:
    sol_spent: int = 0
    neon_income: int = 0


class TxReceiptDetail:
    Type = NewType('TxReceiptDetail', str)
    Eth = Type('ethereum')
    Neon = Type('neon')
    SolTxList = Type('solanaTransactionList')

    TypeList = [Eth, Neon, SolTxList]

    @staticmethod
    def to_type(value: str) -> TxReceiptDetail.Type:
        for detail in TxReceiptDetail.TypeList:
            if detail.upper() == value.upper():
                return detail

        raise InvalidParamError(message='Wrong receipt type')

    @staticmethod
    def to_prop_filter(detail: TxReceiptDetail.Type) -> NeonLogTxEvent.PropFilter:
        if detail == TxReceiptDetail.Eth:
            return NeonLogTxEvent.PropFilter.Eth
        return NeonLogTxEvent.PropFilter.Full


def get_req_id_from_log():
    th = threading.current_thread()
    req_id = getattr(th, "log_context", {}).get("req_id", "")
    return req_id


class NeonRpcApiWorkerData:
    proxy_id_glob = multiprocessing.Value('i', 0)

    def __init__(self, cfg: Config):
        db_conn = DBConnection(cfg)
        self.config = cfg
        self.solana = SolInteractor(cfg)

        self.db = IndexerDB.from_db(cfg, db_conn)
        self.gas_tank = GasLessAccountsDB(db_conn)

        self.core_api_client = NeonCoreApiClient(cfg)
        self.mempool_client = MemPoolClient(MP_SERVICE_ADDR)

        self._gas_price_value: Optional[MPGasPriceResult] = None
        self._gas_price_dict: Dict[int, MPGasPriceTokenResult] = dict()
        self._last_gas_price_time = 0

        self._last_evm_config_time = 0
        self._def_chain_id = 0
        self._is_evm_compatible = False

        with self.proxy_id_glob.get_lock():
            proxy_id = self.proxy_id_glob.value
            self.proxy_id_glob.value += 1

        if proxy_id == 0:
            LOG.debug(f'Neon Proxy version: {self.neon_proxyVersion()}')
        LOG.debug(f'Worker id {proxy_id}')

    def init_evm_config(self) -> None:
        now = math.ceil(time.time())
        if self._last_evm_config_time == now:
            return

        evm_config_data = self.mempool_client.get_evm_config(get_req_id_from_log())
        if (evm_config_data is None) or (not len(evm_config_data.evm_param_list)):
            raise EthereumError(message='Failed to read Neon EVM params from Solana cluster. Try again later')

        evm_config = EVMConfig()
        evm_config.set_evm_config(evm_config_data)

        self._is_evm_compatible = evm_config.is_evm_compatible(NEON_PROXY_PKG_VERSION)
        self._def_chain_id = evm_config.chain_id
        self._last_evm_config_time = now

    def init_gas_price(self) -> None:
        if not self._gas_price_value:
            self._update_gas_price()

    @staticmethod
    def neon_proxyVersion() -> str:
        return 'Neon-proxy/v' + NEON_PROXY_PKG_VERSION + '-' + NEON_PROXY_REVISION

    @property
    def global_gas_price(self) -> MPGasPriceResult:
        self._update_gas_price()
        return cast(MPGasPriceResult, self._gas_price_value)

    def get_gas_price(self, chain_id: int) -> MPGasPriceTokenResult:
        gas_price = self._gas_price_dict.get(chain_id)
        if not gas_price:
            raise EthereumError(message='Failed to calculate gas price. Try again later')
        return gas_price

    def _update_gas_price(self) -> None:
        now = math.ceil(time.time())
        if self._last_gas_price_time != now:
            gas_price = self.mempool_client.get_gas_price(get_req_id_from_log())
            if gas_price:
                self._gas_price_value = gas_price
                self._gas_price_dict.update({
                    token_info.chain_id: token_info
                    for token_info in gas_price.token_list
                })
                self._last_gas_price_time = now

        if not self._gas_price_value:
            raise EthereumError(message='Failed to calculate gas price. Try again later')

    def has_gas_price(self) -> bool:
        return self._gas_price_value is not None

    @property
    def is_evm_compatible(self) -> bool:
        return self._is_evm_compatible

    @property
    def def_chain_id(self) -> int:
        return self._def_chain_id


class NeonRpcApiWorker:
    def __init__(self, data: NeonRpcApiWorkerData, token_name: Optional[str]):
        data.init_evm_config()
        data.init_gas_price()

        self._data = data
        self._evm_config = EVMConfig()
        self._chain_id = self._get_chain_id(token_name)

    def _get_chain_id(self, token_name: Optional[str]) -> int:
        if not token_name:
            return self._data.def_chain_id

        token_name = token_name.upper()
        token_info = self._evm_config.get_token_info_by_name(token_name)
        if not token_info:
            raise EthereumError(message=f'Token {token_name} is not supported.', data={"token_name": token_name})

        return token_info.chain_id

    @cached_property
    def _gas_price(self) -> MPGasPriceTokenResult:
        return self._data.get_gas_price(self._chain_id)

    @cached_property
    def _neon_gas_price(self) -> MPGasPriceTokenResult:
        return self._data.get_gas_price(self._data.def_chain_id)

    @property
    def _config(self) -> Config:
        return self._data.config

    @property
    def _solana(self) -> SolInteractor:
        return self._data.solana

    @property
    def _db(self) -> IndexerDB:
        return self._data.db

    @property
    def _gas_tank(self) -> GasLessAccountsDB:
        return self._data.gas_tank

    @property
    def _core_api_client(self) -> NeonCoreApiClient:
        return self._data.core_api_client

    @property
    def _mempool_client(self) -> MemPoolClient:
        return self._data.mempool_client

    def neon_proxy_version(self) -> str:
        return self.neon_proxyVersion()

    def neon_cli_version(self) -> str:
        return self.neon_cliVersion()

    def neon_evm_version(self) -> str:
        return self.neon_evmVersion()

    def neon_proxyVersion(self) -> str:
        return self._data.neon_proxyVersion()

    def neon_evmVersion(self) -> str:
        return 'Neon/v' + self._evm_config.neon_evm_version + '-' + self._evm_config.neon_evm_revision

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

    def eth_chainId(self) -> str:
        return hex(self._chain_id)

    def net_version(self) -> str:
        return str(self._chain_id)

    def eth_gasPrice(self) -> str:
        return hex(self._gas_price.suggested_gas_price)

    def neon_gasPrice(self, param: Dict[str, Any]) -> str:
        from_addr = param.get('from', None)
        if from_addr is None:
            return self._format_gas_price(self._gas_price.suggested_gas_price)

        from_addr = self._normalize_address(from_addr, 'from-address')

        state_tx_cnt = self._core_api_client.get_state_tx_cnt(from_addr)
        tx_nonce = param.get('nonce', None)
        if tx_nonce is not None:
            tx_nonce = self._normalize_hex(tx_nonce, 'nonce')
        if tx_nonce is None:
            tx_nonce = state_tx_cnt
        else:
            NonceTooLowError.raise_if_error(from_addr.checksum_address, tx_nonce, state_tx_cnt)

        tx_gas = param.get('gas', 0)
        tx_gas = self._normalize_hex(tx_gas, 'gas')

        if self._has_gas_less_tx_permit(from_addr, tx_nonce, tx_gas):
            return self._format_gas_price(0)

        return self._format_gas_price(self._gas_price.suggested_gas_price)

    def _format_gas_price(self, gas_price: int) -> Union[str, Dict[str, str]]:
        global_gas_price_info = self._data.global_gas_price
        token_gas_price_info = self._gas_price
        neon_gas_price_info = self._neon_gas_price

        if token_gas_price_info.is_overloaded:
            gas_price = token_gas_price_info.suggested_gas_price

        return dict(
            gas_price=hex(gas_price),
            suggested_gas_price=hex(token_gas_price_info.suggested_gas_price),
            is_const_gas_price=token_gas_price_info.is_const_gas_price,
            min_acceptable_gas_price=hex(token_gas_price_info.min_acceptable_gas_price),
            min_executable_gas_price=hex(token_gas_price_info.min_executable_gas_price),
            min_wo_chainid_acceptable_gas_price=hex(token_gas_price_info.min_wo_chainid_acceptable_gas_price),
            allow_underpriced_tx_wo_chainid=token_gas_price_info.allow_underpriced_tx_wo_chainid,
            sol_price_usd=hex(global_gas_price_info.sol_price_usd),
            neon_price_usd=hex(neon_gas_price_info.token_price_usd),
            chain_id=hex(token_gas_price_info.chain_id),
            token_name=token_gas_price_info.token_name,
            token_price_usd=hex(token_gas_price_info.token_price_usd),
            operator_fee=hex(token_gas_price_info.operator_fee),
            gas_price_slippage=hex(token_gas_price_info.gas_price_slippage)
        )

    @staticmethod
    def _normalize_hex(value: Union[str, int], name: str) -> int:
        try:
            if isinstance(value, int):
                pass
            elif isinstance(value, str):
                value = value.lower()
                if value.startswith('0x'):
                    value = int(value, 16)
                else:
                    value = int(value, 10)
            else:
                assert False

            assert value >= 0
            return value
        except (Exception,):
            raise InvalidParamError(f'invalid {name}: value')

    def _has_gas_less_tx_permit(self, addr: NeonAddress, tx_nonce: int, tx_gas_limit: int) -> bool:
        if self._config.gas_less_tx_max_nonce < tx_nonce:
            return False
        if self._config.gas_less_tx_max_gas < tx_gas_limit:
            return False

        return self._gas_tank.has_gas_less_tx_permit(addr)

    def eth_estimateGas(self, param: Dict[str, Any], tag: Union[str, int, dict] = 'latest') -> str:
        block = self._process_block_tag(tag)

        if not isinstance(param, dict):
            raise InvalidParamError('invalid param')
        if 'from' in param:
            param['from'] = self._normalize_address(param['from'], 'from-address')
        if 'to' in param:
            param['to'] = self._normalize_address(param['to'], 'to-address')

        try:
            calculator = GasEstimate(self._core_api_client, self._chain_id)
            return hex(calculator.estimate(param, block))

        except EthereumError:
            raise
        except BaseException as exc:
            LOG.debug(f"Exception on eth_estimateGas: {str(exc)}")
            raise

    def __repr__(self):
        return str(self.__dict__)

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

    def _normalize_address(self, raw_address: str, address_type='address') -> NeonAddress:
        try:
            address = raw_address.strip().lower()
            assert address[:2] == '0x'

            bin_address = hex_to_bytes(address)
            assert len(bin_address) == 20

            return NeonAddress.from_raw(bin_address, self._chain_id)
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
        addr = self._normalize_address(account)

        try:
            neon_acct_info = self._core_api_client.get_neon_account_info(addr, block)
            if neon_acct_info.balance == 0:
                return self._get_zero_balance(addr, neon_acct_info)

            return hex(neon_acct_info.balance)
        except (Exception,):
            # LOG.debug(f"eth_getBalance: Can't get account info: {err}")
            return hex(0)

    def _get_zero_balance(self, addr: NeonAddress, neon_account_info: Optional[NeonAccountInfo]) -> str:
        nonce = neon_account_info.tx_count if neon_account_info is not None else 0
        if self._has_gas_less_tx_permit(addr, nonce, 0):
            return hex(1)
        return hex(0)

    @staticmethod
    def _normalize_topic(raw_topic: Any) -> str:
        try:
            assert isinstance(raw_topic, str)

            topic = raw_topic.strip().lower()
            assert topic[:2] == '0x'

            bin_topic = hex_to_bytes(topic)
            assert len(bin_topic) == 32

            return '0x' + bin_topic.hex().lower()
        except (Exception,):
            raise InvalidParamError(message=f'bad topic {raw_topic}')

    def _get_event_list(self, obj: Dict[str, Any]) -> List[NeonLogTxEvent]:
        from_block: Optional[int] = None
        to_block: Optional[int] = None
        address_list: List[str] = list()
        topic_list: List[List[str]] = list()

        if not isinstance(obj, dict):
            raise InvalidParamError(message=f'invalid input params: {obj}')

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
                address_list = [self._normalize_address(raw_address_list).address]
            elif isinstance(raw_address_list, list):
                for raw_address in raw_address_list:
                    address_list.append(self._normalize_address(raw_address).address)
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

        return self._db.get_event_list(from_block, to_block, address_list, topic_list)

    @staticmethod
    def _filter_event_list(event_list: Iterable[NeonLogTxEvent],
                           prop_filter: NeonLogTxEvent.PropFilter) -> List[Dict[str, Any]]:
        return [
            event.as_rpc_dict(prop_filter)
            for event in event_list
            if event.has_rpc_dict(prop_filter)
        ]

    def eth_getLogs(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        event_list = self._get_event_list(obj)
        return self._filter_event_list(event_list, NeonLogTxEvent.PropFilter.Eth)

    def neon_getLogs(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        event_list = self._get_event_list(obj)
        return self._filter_event_list(event_list, NeonLogTxEvent.PropFilter.Full)

    def _get_block_by_slot(self, block: SolBlockInfo, full: bool, skip_transaction: bool) -> Optional[dict]:
        if block.is_empty():
            return None

        sig_list = list()

        log_bloom = 0
        total_gas_used = 0
        if skip_transaction:
            tx_list = list()
        else:
            tx_list = self._db.get_tx_list_by_block_slot(block.block_slot)

        for tx in tx_list:
            total_gas_used = max(tx.neon_tx_res.sum_gas_used, total_gas_used)
            log_bloom |= tx.neon_tx_res.log_bloom

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
            "logsBloom": u256big_to_hex(log_bloom),
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

            bin_block_hash = hex_to_bytes(block_hash)
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

    def eth_call(self, obj: dict, tag: Union[int, str, dict], state: Optional[dict] = None) -> str:
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
            if sender:
                sender = self._normalize_address(sender, 'from-address')

            contract = obj.get('to')
            if contract:
                contract = self._normalize_address(contract, 'to-address')

            data = obj.get('data')
            value = obj.get('value')
            gas_limit = obj.get('gas')

            emulator_result = self._core_api_client.emulate(
                contract, sender, self._chain_id, data, value, gas_limit, block, check_result=True
            )
            return '0x' + emulator_result.result

        except EthereumError:
            raise

        except Exception as err:
            LOG.debug(f'eth_call Exception {err}.')
            raise

    def eth_getTransactionCount(self, account: str, tag: Union[str, int, dict]) -> str:
        block = self._process_block_tag(tag) if tag != 'mempool' else None
        addr = self._normalize_address(account)

        try:
            LOG.debug(f'Get transaction count. Account: {str(addr)}, tag: {tag}')

            mempool_tx_nonce: Optional[int] = None
            req_id = get_req_id_from_log()

            if tag == 'mempool':
                mempool_tx_nonce = self._mempool_client.get_mempool_tx_nonce(req_id=req_id, sender=addr)
                LOG.debug(f'Mempool tx count for: {str(addr)} - is: {mempool_tx_nonce}')

            elif (block is not None) and (block.sol_commit == SolCommit.Processed):
                mempool_tx_nonce = self._mempool_client.get_pending_tx_nonce(req_id=req_id, sender=addr)
                LOG.debug(f'Pending tx count for: {str(addr)} - is: {mempool_tx_nonce}')

            if mempool_tx_nonce is None:
                mempool_tx_nonce = 0

            tx_cnt = self._core_api_client.get_state_tx_cnt(addr, block)
            tx_cnt = max(tx_cnt, mempool_tx_nonce)

            return hex(tx_cnt)
        except (Exception,):
            # LOG.debug(f"eth_getTransactionCount: Can't get account info: {err}")
            return hex(0)

    def neon_getAccount(self, account: str, tag: Union[str, int, dict]) -> Dict[str, Any]:
        addr = self._normalize_address(account)
        block = self._process_block_tag(tag)
        acct = self._core_api_client.get_neon_account_info(addr, block)
        return dict(
            status=acct.status.value,
            address=addr.checksum_address,
            transactionCount=hex(acct.tx_count),
            balance=hex(acct.balance),
            chainId=hex(acct.chain_id),
            solanaAddress=str(acct.solana_address),
            contractSolanaAddress=str(acct.contract_solana_address),
        )

    def _fill_transaction_receipt_answer(self, tx: NeonTxReceiptInfo, details: TxReceiptDetail.Type) -> dict:
        contract = NeonAddress.from_raw(tx.neon_tx.contract)
        if contract:
            contract = contract.checksum_address

        to_addr = NeonAddress.from_raw(tx.neon_tx.to_addr)
        if to_addr:
            to_addr = to_addr.checksum_address

        res = tx.neon_tx_res

        receipt = {
            "transactionHash": tx.neon_tx.sig,
            "transactionIndex": hex(res.tx_idx),
            "type": hex(tx.neon_tx.tx_type),
            "blockHash": res.block_hash,
            "blockNumber": hex(res.block_slot),
            "from": NeonAddress.from_raw(tx.neon_tx.addr).checksum_address,
            "to": to_addr,
            "gasUsed": hex(res.gas_used),
            "cumulativeGasUsed": hex(res.sum_gas_used),
            "contractAddress": contract,
            "status": hex(res.status),
            "logsBloom": u256big_to_hex(res.log_bloom)
        }

        if details != TxReceiptDetail.SolTxList:
            receipt['logs'] = self._filter_event_list(
                tx.neon_tx_res.event_list,
                TxReceiptDetail.to_prop_filter(details)
            )

        if details == TxReceiptDetail.Eth:
            return receipt

        inner_idx = None if tx.neon_tx_res.sol_ix_inner_idx is None else hex(res.sol_ix_inner_idx)
        receipt.update({
            'solanaBlockHash': base58.b58encode(hex_to_bytes(res.block_hash)).decode('utf-8'),
            'solanaCompleteTransactionHash': tx.neon_tx_res.sol_sig,
            'solanaCompleteInstructionIndex': hex(tx.neon_tx_res.sol_ix_idx),
            'solanaCompleteInnerInstructionIndex': inner_idx,
            'neonRawTransaction': '0x' + tx.neon_tx.as_raw_tx().hex(),
            'neonIsCompleted': res.is_completed,
            'neonIsCanceled': res.is_canceled
        })

        if details != TxReceiptDetail.SolTxList:
            return receipt

        self._fill_sol_tx_info_list(tx, receipt)
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

            result_ix_list.append({
                'solanaProgram': 'NeonEVM',
                'solanaInstructionIndex': hex(neon_ix.idx),
                'solanaInnerInstructionIndex': hex(neon_ix.inner_idx) if neon_ix.inner_idx else None,
                'svmHeapSizeLimit': hex(neon_ix.max_heap_size),
                'svmHeapSizeUsed': hex(neon_ix.used_heap_size),
                'svmCyclesLimit': hex(neon_ix.max_bpf_cycle_cnt),
                'svmCyclesUsed': hex(neon_ix.used_bpf_cycle_cnt),
                'neonInstructionCode': hex(neon_ix.ix_code),
                'neonInstructionName': EvmIxCodeName().get(neon_ix.ix_code),
                'neonStepLimit': hex(neon_ix.neon_step_cnt) if neon_ix.neon_step_cnt else None,
                'neonAlanIncome': hex(neon_income),
                'neonGasUsed': hex(neon_ix.neon_gas_used),
                'neonTotalGasUsed': hex(neon_ix.neon_total_gas_used),
                'neonLogs': full_log_dict.get(neon_ix.str_ident, None),
            })

        sol_sig = ''
        for alt_ix in sol_alt_ix_list:
            if alt_ix.sol_sig != sol_sig:
                sol_sig = alt_ix.sol_sig
                result_ix_list, op_cost = _fill_sol_tx(alt_ix)

            result_ix_list.append({
                'solanaProgram': 'AddressLookupTable',
                'solanaInstructionIndex': hex(alt_ix.idx),
                'solanaInnerInstructionIndex': hex(alt_ix.inner_idx) if alt_ix.inner_idx else None,
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

    @staticmethod
    def _get_full_log_dict(tx: NeonTxReceiptInfo) -> Dict[str, List[Dict[str, Any]]]:
        full_log_dict: Dict[str, List[Dict[str, Any]]] = dict()
        for event in tx.neon_tx_res.event_list:
            full_log_dict.setdefault(event.str_ident, list()).append(
                event.as_rpc_dict(NeonLogTxEvent.PropFilter.Neon)
            )

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
        return self._fill_transaction_receipt_answer(tx, TxReceiptDetail.Eth)

    def neon_getTransactionReceipt(self, neon_tx_sig: str, details: str = TxReceiptDetail.SolTxList) -> Optional[dict]:
        tx = self._get_transaction_receipt(neon_tx_sig)
        if tx is None:
            return None
        return self._fill_transaction_receipt_answer(tx, TxReceiptDetail.to_type(details))

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

        to_addr = NeonAddress.from_raw(t.to_addr)
        if to_addr:
            to_addr = to_addr.checksum_address

        from_addr = NeonAddress.from_raw(t.addr)
        if from_addr:
            from_addr = from_addr.checksum_address
        else:
            from_addr = '0x' + '0' * 40

        result = {
            "blockHash": r.block_hash,
            "blockNumber": hex_block_number,
            "hash": t.sig,
            "transactionIndex": hex_tx_idx,
            "type": hex(t.tx_type),
            "from": from_addr,
            "nonce": hex(t.nonce),
            "gasPrice": hex(t.gas_price),
            "gas": hex(t.gas_limit),
            "to": to_addr,
            "value": hex(t.value),
            "input": t.calldata,
            "v": hex(t.v),
            "r": hex(t.r),
            "s": hex(t.s),
            "chainId": hex(t.chain_id) if t.has_chain_id() else None
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

    def neon_getTransactionBySenderNonce(self, account: str, nonce: Union[int, str]) -> Optional[Dict[str, Any]]:
        addr = self._normalize_address(account)
        tx_nonce = self._normalize_hex(nonce, 'nonce')

        neon_tx_receipt: NeonTxReceiptInfo = self._db.get_tx_by_sender_nonce(addr.address, tx_nonce)
        if neon_tx_receipt is None:
            neon_tx: MPNeonTxResult = self._mempool_client.get_pending_tx_by_sender_nonce(
                get_req_id_from_log(), addr, tx_nonce
            )
            if neon_tx is None:
                LOG.debug("Not found receipt")
                return None
            elif isinstance(neon_tx, EthereumError):
                raise neon_tx

        return self._get_transaction(neon_tx_receipt)

    def eth_getCode(self, contract: str, tag: Union[str, int, dict]) -> str:
        block = self._process_block_tag(tag)
        contract = self._normalize_address(contract)

        try:
            contract_info = self._core_api_client.get_neon_contract_info(contract, block)
            return contract_info.code
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
                get_req_id_from_log(), neon_tx, self._data.def_chain_id, neon_tx_exec_cfg
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
        tx_sender = NeonAddress.from_raw(neon_tx.sender, neon_tx.chain_id)
        tx_nonce = int(neon_tx.nonce)
        block = self._process_block_tag(EthCommit.Finalized)
        state_tx_cnt = self._core_api_client.get_state_tx_cnt(tx_sender, block)
        NonceTooLowError.raise_if_error(tx_sender.checksum_address, tx_nonce, state_tx_cnt)

    def _get_neon_tx_exec_cfg(self, neon_tx: NeonTx) -> NeonTxExecCfg:
        gas_less_permit = False
        if neon_tx.gasPrice == 0:
            tx_sender = NeonAddress.from_raw(neon_tx.sender, self._chain_id)
            gas_less_permit = self._has_gas_less_tx_permit(tx_sender, neon_tx.nonce, neon_tx.gasLimit)

        min_gas_price = self._gas_price.min_executable_gas_price
        chain_id_list = [self._chain_id, None] if self._data.def_chain_id == self._chain_id else [self._chain_id]
        neon_tx_validator = NeonTxValidator(self._config, self._core_api_client, self._chain_id, chain_id_list)
        neon_tx_exec_cfg = neon_tx_validator.validate(neon_tx, gas_less_permit, min_gas_price)
        return neon_tx_exec_cfg

    def _get_transaction_by_index(self, block: SolBlockInfo, tx_idx: Union[str, int]) -> Optional[Dict[str, Any]]:
        tx_idx = self._normalize_hex(tx_idx, 'transaction index')

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
        return [a.checksum_address for a in account_list]

    def eth_sign(self, account: str, data: str) -> str:
        address = self._normalize_address(account)
        try:
            data = hex_to_bytes(data)
        except (Exception,):
            raise InvalidParamError(message='data is not hex string')

        account = KeyStorage().get_key(address)
        if not account:
            raise EthereumError(message='unknown account')

        message = str.encode(f'\x19Ethereum Signed Message:\n{len(data)}') + data
        return str(account.private_key.sign_msg(message))

    def eth_signTransaction(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        if 'from' not in tx:
            raise InvalidParamError(message='no sender in transaction')

        sender = tx['from']
        del tx['from']
        sender = self._normalize_address(sender, 'from-address')

        if 'to' in tx:
            tx['to'] = self._normalize_address(tx['to'], 'to-address').checksum_address

        account = KeyStorage().get_key(sender)
        if not account:
            raise EthereumError(message='unknown account')

        if 'nonce' not in tx:
            tx['nonce'] = self.eth_getTransactionCount(sender.address, EthCommit.Pending)

        if 'chainId' not in tx:
            tx['chainId'] = hex(self._chain_id)

        try:
            signed_tx = NeonAccount().sign_transaction(tx, account.private_key)
            raw_tx = signed_tx.rawTransaction.hex()
            neon_tx = NeonTx.from_string(bytearray.fromhex(raw_tx[2:]))

            tx.update({
                'from': sender.checksum_address,
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
            LOG.error('Failed on sign transaction', exc_info=exc)
            raise InvalidParamError(message='bad transaction')

    def eth_sendTransaction(self, tx: Dict[str, Any]) -> str:
        tx = self.eth_signTransaction(tx)
        return self.eth_sendRawTransaction(tx['raw'])

    @staticmethod
    def web3_sha3(data: str) -> str:
        try:
            data = hex_to_bytes(data)
        except (Exception,):
            raise InvalidParamError(message='data is not hex string')

        return '0x' + keccak_256(data).hexdigest()

    @staticmethod
    def eth_mining() -> bool:
        return False

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
        to_addr = NeonAddress.from_raw(neon_tx_info.to_addr)
        if to_addr:
            to_addr = to_addr.checksum_address

        return {
            'blockHash': '0x' + '0' * 64,
            'blockNumber': None,
            'transactionIndex': None,
            'from': NeonAddress.from_raw(neon_tx_info.addr).checksum_address,
            'gas': hex(neon_tx_info.gas_limit),
            'gasPrice': hex(neon_tx_info.gas_price),
            'hash': neon_tx_info.sig,
            'input': neon_tx_info.calldata,
            'nonce': hex(neon_tx_info.nonce),
            'to': to_addr,
            'value': hex(neon_tx_info.value),
            'chainId': hex(neon_tx_info.chain_id) if neon_tx_info.has_chain_id() else None
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
        for sol_tx in sol_tx_list:
            if sol_tx is None:
                return sol_sig_list
        return sol_sig_list

    def neon_emulate(self, raw_signed_tx: str):
        """Executes emulator with given transaction"""
        LOG.debug(f'Call neon_emulate: {raw_signed_tx}')

        neon_tx = NeonTx.from_string(bytearray.fromhex(raw_signed_tx))
        chain_id = neon_tx.chain_id or self._chain_id
        emulator_result = self._core_api_client.emulate_neon_tx(neon_tx, chain_id)
        return emulator_result.full_dict

    def neon_finalizedBlockNumber(self) -> str:
        slot = self._db.finalized_slot
        return hex(slot)

    def neon_earliestBlockNumber(self) -> str:
        slot = self._db.earliest_slot
        return hex(slot)

    def neon_getEvmParams(self) -> Dict[str, str]:
        """Returns map of Neon-EVM parameters"""
        evm_param_dict = self._evm_config.evm_param_dict
        evm_param_dict['NEON_EVM_ID'] = EVM_PROGRAM_ID_STR
        return evm_param_dict

    def neon_getNativeTokenList(self) -> List[Dict[str, str]]:
        return list(
            dict(
                token_name=token.token_name,
                token_mint=str(token.token_mint),
                token_chain_id=hex(token.chain_id)
            )
            for token in self._evm_config.token_info_list
        )

    def is_allowed_api(self, method_name: str) -> bool:
        for prefix in ('eth_', 'net_', 'web3_', 'neon_', 'txpool_'):
            if method_name.startswith(prefix):
                break
        else:
            return False

        always_allowed_method_set = {
            "neon_proxyVersion",
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
            return True

        if not self._data.is_evm_compatible:
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
