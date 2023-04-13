import math
import threading
import multiprocessing
import time
import logging
from typing import Optional, Union, Dict, Any, List, cast

import eth_utils
from sha3 import keccak_256

from eth_account import Account as NeonAccount

from ..common_neon.address import NeonAddress
from ..common_neon.config import Config
from ..common_neon.elf_params import ElfParams
from ..common_neon.emulator_interactor import call_emulated, check_emulated_exit_status, call_tx_emulated
from ..common_neon.environment_utils import NeonCli
from ..common_neon.errors import EthereumError, InvalidParamError, RescheduleError
from ..common_neon.estimate import GasEstimate
from ..common_neon.eth_proto import NeonTx
from ..common_neon.keys_storage import KeyStorage
from ..common_neon.solana_tx import SolCommit
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.transaction_validator import NeonTxValidator
from ..common_neon.utils import SolBlockInfo, NeonTxReceiptInfo, NeonTxInfo, NeonTxResultInfo

from ..indexer.indexer_db import IndexerDB

from ..mempool import MemPoolClient, MP_SERVICE_ADDR, MPTxSendResult, MPTxSendResultCode, MPGasPriceResult

NEON_PROXY_PKG_VERSION = '0.15.0-dev'
NEON_PROXY_REVISION = 'NEON_PROXY_REVISION_TO_BE_REPLACED'
LOG = logging.getLogger(__name__)


def get_req_id_from_log():
    th = threading.current_thread()
    req_id = getattr(th, "log_context", {}).get("req_id", "")
    return req_id


class NeonRpcApiWorker:
    proxy_id_glob = multiprocessing.Value('i', 0)

    def __init__(self, config: Config):
        self._config = config
        self._solana = SolInteractor(self._config, self._config.solana_url)
        self._db = IndexerDB(config)
        self._mempool_client = MemPoolClient(MP_SERVICE_ADDR)

        self._gas_price_value: Optional[MPGasPriceResult] = None
        self._last_gas_price_time = 0

        self._last_elf_params_time = 0

        with self.proxy_id_glob.get_lock():
            self.proxy_id = self.proxy_id_glob.value
            self.proxy_id_glob.value += 1

        if self.proxy_id == 0:
            LOG.debug(f'Neon Proxy version: {self.neon_proxy_version()}')
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

    @staticmethod
    def neon_proxyVersion() -> str:
        return 'Neon-proxy/v' + NEON_PROXY_PKG_VERSION + '-' + NEON_PROXY_REVISION

    @staticmethod
    def web3_clientVersion() -> str:
        return 'Neon/v' + ElfParams().neon_evm_version + '-' + ElfParams().neon_evm_revision

    @staticmethod
    def eth_chainId() -> str:
        return hex(ElfParams().chain_id)

    def neon_cli_version(self) -> str:
        return self.neon_cliVersion()

    def neon_cliVersion(self) -> str:
        return NeonCli(self._config).version()

    @staticmethod
    def net_version() -> str:
        return str(ElfParams().chain_id)

    def eth_gasPrice(self) -> str:
        return hex(self._gas_price.suggested_gas_price)

    def eth_estimateGas(self, param: Dict[str, Any]) -> str:
        if not isinstance(param, dict):
            raise InvalidParamError('invalid param')
        if 'from' in param:
            param['from'] = self._normalize_address(param['from'])
        if 'to' in param:
            param['to'] = self._normalize_address(param['to'])

        try:
            calculator = GasEstimate(self._config, self._solana, param)
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
        return tag == 'earliest' \
            or ((tag == '0x0' or str(tag) == '0') and self._config.use_earliest_block_if_0_passed)

    def _process_block_tag(self, tag: Union[str, int]) -> SolBlockInfo:
        if tag == 'latest':
            block = self._db.get_latest_block()
        elif tag == 'pending':
            latest_block = self._db.get_latest_block()
            block = SolBlockInfo(
                block_slot=latest_block.block_slot + 1,
                block_time=latest_block.block_time,
                parent_block_hash=latest_block.block_hash,
                parent_block_slot=latest_block.block_slot
            )
        elif tag in {'finalized', 'safe'}:
            block = self._db.get_finalized_block()
        elif self._should_return_starting_block(tag):
            block = self._db.get_starting_block()
        elif isinstance(tag, str):
            try:
                block = SolBlockInfo(block_slot=int(tag.strip(), 16))
            except (Exception,):
                raise InvalidParamError(message=f'failed to parse block tag: {tag}')
        elif isinstance(tag, int):
            block = SolBlockInfo(block_slot=tag)
        else:
            raise InvalidParamError(message=f'failed to parse block tag: {tag}')
        return block

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

    def _validate_block_tag(self, tag: Union[int, str, dict]) -> None:
        try:
            if isinstance(tag, int):
                pass
            elif isinstance(tag, str):
                tag.strip().lower()
                if tag in {'latest', 'pending', 'earliest', 'finalized', 'safe'}:
                    return

                assert tag[:2] == '0x'
                int(tag[2:], 16)
            elif isinstance(tag, dict):
                block_hash = tag['blockHash']
                block = self._get_block_by_hash(block_hash)
                if block.is_empty():
                    raise InvalidParamError(message=f'header for hash {block_hash} not found')
            else:
                assert False, 'Bad type of tag'
        except (InvalidParamError, ):
            raise
        except (Exception,):
            raise InvalidParamError(message=f'invalid block tag {tag}')

    @staticmethod
    def _normalize_address(raw_address: str, error='bad account') -> str:
        try:
            address = raw_address.strip().lower()
            assert address[:2] == '0x'
            address = address[2:]

            bin_address = bytes.fromhex(address)
            assert len(bin_address) == 20

            return eth_utils.to_checksum_address(address)
        except (Exception,):
            raise InvalidParamError(message=error)

    def _get_full_block_by_number(self, tag: Union[str, int]) -> SolBlockInfo:
        block = self._process_block_tag(tag)
        if block.is_empty():
            block = self._db.get_block_by_slot(block.block_slot)
            if block.is_empty():
                LOG.debug(f"Not found block by slot {block.block_slot}")

        return block

    def eth_blockNumber(self) -> str:
        slot = self._db.get_latest_block_slot()
        return hex(slot)

    def eth_getBalance(self, account: str, tag: Union[int, str]) -> str:
        """account - address to check for balance.
           tag - integer block number, or the string "finalized", "safe", "latest", "earliest" or "pending"
        """

        self._validate_block_tag(tag)
        account = self._normalize_address(account)

        try:
            if tag == 'pending':
                commitment = SolCommit.Processed
            elif tag in {'finalized', 'safe'}:
                commitment = SolCommit.Finalized
            else:
                commitment = SolCommit.Confirmed

            neon_account_info = self._solana.get_neon_account_info(NeonAddress(account), commitment)
            if neon_account_info is None:
                return hex(0)

            return hex(neon_account_info.balance)
        except (Exception,):
            # LOG.debug(f"eth_getBalance: Can't get account info: {err}")
            return hex(0)

    @staticmethod
    def _update_event_type(log_rec: Dict[str, Any]) -> None:
        key = 'neonEventType'
        event_type = log_rec.get(key, None)
        if event_type is None:
            return

        if event_type == 1:
            log_rec[key] = 'LOG'
        elif event_type == 101:
            log_rec[key] = 'ENTER CALL'
        elif event_type == 102:
            log_rec[key] = 'ENTER CALL CODE'
        elif event_type == 103:
            log_rec[key] = 'ENTER STATICCALL'
        elif event_type == 104:
            log_rec[key] = 'ENTER DELEGATECALL'
        elif event_type == 105:
            log_rec[key] = 'ENTER CREATE'
        elif event_type == 106:
            log_rec[key] = 'ENTER CREATE2'
        elif event_type == 201:
            log_rec[key] = 'EXIT STOP'
        elif event_type == 202:
            log_rec[key] = 'EXIT RETURN'
        elif event_type == 203:
            log_rec[key] = 'EXIT SELFDESTRUCT'
        elif event_type == 204:
            log_rec[key] = 'EXIT REVERT'
        elif event_type == 300:
            log_rec[key] = 'RETURN'
        elif event_type == 301:
            log_rec[key] = 'CANCEL'

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

    def _get_logs(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        from_block: Optional[int] = None
        to_block: Optional[int] = None
        address_list: List[str] = list()
        topic_list: List[List[str]] = list()

        if 'fromBlock' in obj and obj['fromBlock'] != '0':
            from_block = self._process_block_tag(obj['fromBlock']).block_slot
        if 'toBlock' in obj and obj['toBlock'] not in {'latest', 'pending', 'finalized', 'safe'}:
            to_block = self._process_block_tag(obj['toBlock']).block_slot

        if 'blockHash' in obj:
            block_hash = obj['blockHash']
            block = self._get_block_by_hash(block_hash)
            if block.is_empty():
                raise InvalidParamError(message=f'block hash {block_hash} does not exist')
            from_block = block.block_slot
            to_block = block.block_slot

        if 'address' in obj:
            raw_address_list = obj['address']
            if isinstance(raw_address_list, str):
                address_list = [self._normalize_address(raw_address_list, f'bad address {raw_address_list}').lower()]
            elif isinstance(raw_address_list, list):
                for raw_address in raw_address_list:
                    address_list.append(self._normalize_address(raw_address, f'bad address {raw_address}').lower())
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
                    topic_list.append([self._normalize_topic(raw_item) for raw_item in raw_topic])
                else:
                    topic_list.append([self._normalize_topic(raw_topic)])

        return self._db.get_log_list(from_block, to_block, address_list, topic_list)

    def _filter_log_list(self, log_list: List[Dict[str, Any]], with_hidden) -> List[Dict[str, Any]]:
        filtered_log_list: List[Dict[str, Any]] = list()

        for log_rec in log_list:
            if log_rec.get('neonIsHidden', False) and (not with_hidden):
                continue

            log_rec['removed'] = False

            # remove fields available only for neon_getLogs
            if not with_hidden:
                remove_key_list: List[str] = list()
                for key in log_rec.keys():
                    if key[:4] == 'neon':
                        remove_key_list.append(key)

                for key in remove_key_list:
                    log_rec.pop(key, None)

            else:
                self._update_event_type(log_rec)

            if log_rec['data'] == '':
                log_rec['data'] = '0x'

            filtered_log_list.append(log_rec)
        return filtered_log_list

    def eth_getLogs(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        log_list = self._get_logs(obj)
        return self._filter_log_list(log_list, False)

    def neon_getLogs(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        log_list = self._get_logs(obj)
        return self._filter_log_list(log_list, True)

    def _get_block_by_slot(self, block: SolBlockInfo, full: bool, skip_transaction: bool) -> Optional[dict]:
        if block.is_empty():
            block = self._db.get_block_by_slot(block.block_slot)
            if block.is_empty():
                return None

        sig_list = []
        gas_used = 0
        if skip_transaction:
            tx_list = []
        else:
            tx_list = self._db.get_tx_list_by_block_slot(block.block_slot)

        for tx in tx_list:
            try:
                gas_used += int(tx.neon_tx_res.gas_used, 16)
            except ValueError:
                pass

            if full:
                receipt = self._get_transaction(tx)
                sig_list.append(receipt)
            else:
                sig_list.append(tx.neon_tx.sig)

        result = {
            "difficulty": '0x0',
            "totalDifficulty": '0x0',
            "extraData": "0x" + '0' * 63 + '1',
            "logsBloom": '0x' + '0' * 512,
            "gasLimit": '0xec8563e271ac',
            "transactionsRoot": '0x' + '0' * 63 + '1',
            "receiptsRoot": '0x' + '0' * 63 + '1',
            "stateRoot": '0x' + '0' * 63 + '1',

            "uncles": [],
            "sha3Uncles": '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347',

            "miner": '0x' + '0' * 40,
            # 8 byte nonce
            "nonce": '0x0000000000000000',
            "mixHash": '0x' + '0' * 63 + '1',
            "size": '0x' + '1',

            "gasUsed": hex(gas_used),
            "hash": block.block_hash,
            "number": hex(block.block_slot),
            "parentHash": block.parent_block_hash,
            "timestamp": hex(block.block_time),
            "transactions": sig_list,
        }
        return result

    def eth_getStorageAt(self, account: str, position, tag: Union[int, str]) -> str:
        """
        Retrieves storage data by given position
        Currently supports only 'latest' block
        """

        self._validate_block_tag(tag)
        account = self._normalize_address(account)

        try:
            value = NeonCli(self._config).call('get-storage-at', account, position)
            return '0x' + (value or 64*'0')
        except (Exception,):
            # LOG.error(f"eth_getStorageAt: Neon-cli failed to execute: {err}")
            return '0x' + 64*'0'

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
            tag - integer of a block number, or the string "finalized", "safe", "earliest", "latest" or "pending", as in the default block parameter.
            full - If true it returns the full transaction objects, if false only the hashes of the transactions.
        """
        is_pending = tag == 'pending'
        block = self._process_block_tag(tag)
        ret = self._get_block_by_slot(block, full, is_pending)
        if is_pending:
            ret['miner'] = None
            ret['hash'] = None
            ret['nonce'] = None
        return ret

    def eth_call(self, obj: dict, tag: Union[int, str]) -> str:
        """Executes a new message call immediately without creating a transaction on the block chain.
           Parameters
            obj - The transaction call object
                from: DATA, 20 Bytes - (optional) The address the transaction is sent from.
                to: DATA, 20 Bytes - The address the transaction is directed to.
                gas: QUANTITY - (optional) Integer of the gas provided for the transaction execution. eth_call consumes zero gas, but this parameter may be needed by some executions.
                gasPrice: QUANTITY - (optional) Integer of the gasPrice used for each paid gas
                value: QUANTITY - (optional) Integer of the value sent with this transaction
                data: DATA - (optional) Hash of the method signature and encoded parameters. For details see Ethereum Contract ABI in the Solidity documentation
            tag - integer block number, or the string "finalized", "safe", "latest", "earliest" or "pending", see the default block parameter
        """
        self._validate_block_tag(tag)
        if not isinstance(obj, dict):
            raise InvalidParamError(message='invalid object type')

        if not obj['data']:
            raise InvalidParamError(message="missing data")

        try:
            caller_id = obj.get('from', "0x0000000000000000000000000000000000000000")
            contract_id = obj.get('to', 'deploy')
            data = obj.get('data', "None")
            value = obj.get('value', '')

            retry_idx = 0
            retry_on_fail = self._config.retry_on_fail
            while True:
                try:
                    emulator_json = call_emulated(self._config, contract_id, caller_id, data, value)
                    check_emulated_exit_status(emulator_json)
                    return '0x' + emulator_json['result']

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

    def eth_getTransactionCount(self, account: str, tag: Union[str, int]) -> str:
        self._validate_block_tag(tag)
        account = self._normalize_address(account).lower()

        try:
            LOG.debug(f'Get transaction count. Account: {account}, tag: {tag}')

            pending_tx_nonce: Optional[int] = None
            commitment = SolCommit.Confirmed
            req_id = get_req_id_from_log()

            if tag == 'pending':
                commitment = SolCommit.Processed

                pending_tx_nonce = self._mempool_client.get_pending_tx_nonce(req_id=req_id, sender=account)
                LOG.debug(f'Pending tx count for: {account} - is: {pending_tx_nonce}')
            elif tag == 'latest':
                commitment = SolCommit.Processed

                pending_tx_nonce = self._mempool_client.get_mempool_tx_nonce(req_id=req_id, sender=account)
                LOG.debug(f'Mempool tx count for: {account} - is: {pending_tx_nonce}')
            elif tag in {'finalized', 'safe'}:
                commitment = SolCommit.Finalized

            if pending_tx_nonce is None:
                pending_tx_nonce = 0

            neon_account_info = self._solana.get_neon_account_info(account, commitment)
            tx_count = max(neon_account_info.tx_count, pending_tx_nonce)

            return hex(tx_count)
        except (Exception,):
            # LOG.debug(f"eth_getTransactionCount: Can't get account info: {err}")
            return hex(0)

    def _fill_transaction_receipt_answer(self, tx: NeonTxReceiptInfo, with_hidden: bool) -> dict:
        log_list = self._filter_log_list(tx.neon_tx_res.log_list, with_hidden)

        result = {
            "transactionHash": tx.neon_tx.sig,
            "transactionIndex": hex(tx.neon_tx_res.tx_idx),
            "type": "0x0",
            "blockHash": tx.neon_tx_res.block_hash,
            "blockNumber": hex(tx.neon_tx_res.block_slot),
            "from": tx.neon_tx.addr,
            "to": tx.neon_tx.to_addr,
            "gasUsed": tx.neon_tx_res.gas_used,
            "cumulativeGasUsed": tx.neon_tx_res.gas_used,
            "contractAddress": tx.neon_tx.contract,
            "logs": log_list,
            "status": tx.neon_tx_res.status,
            "logsBloom": "0x" + '0' * 512
        }

        return result

    def _get_transaction_receipt(self, neon_tx_sig: str) -> Optional[NeonTxReceiptInfo]:
        neon_sig = self._normalize_tx_id(neon_tx_sig)

        tx = self._db.get_tx_by_neon_sig(neon_sig)
        if not tx:
            neon_tx_or_error = self._mempool_client.get_pending_tx_by_hash(get_req_id_from_log(), neon_tx_sig)
            if isinstance(neon_tx_or_error, EthereumError):
                raise neon_tx_or_error
            return None
        return tx

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
    def _get_transaction(tx: NeonTxReceiptInfo) -> dict:
        t = tx.neon_tx
        r = tx.neon_tx_res

        block_number = None
        if r.block_slot is not None:
            block_number = hex(r.block_slot)

        tx_idx = None
        if r.tx_idx is not None:
            tx_idx = hex(r.tx_idx)

        result = {
            "blockHash": r.block_hash,
            "blockNumber": block_number,
            "hash": t.sig,
            "transactionIndex": tx_idx,
            "type": "0x0",
            "from": t.addr,
            "nonce":  t.nonce,
            "gasPrice": t.gas_price,
            "gas": t.gas_limit,
            "to": t.to_addr,
            "value": t.value,
            "input": t.calldata,
            "v": t.v,
            "r": t.r,
            "s": t.s,
        }

        return result

    def eth_getTransactionByHash(self, neon_tx_sig: str) -> Optional[dict]:
        neon_sig = self._normalize_tx_id(neon_tx_sig)

        neon_tx_receipt: NeonTxReceiptInfo = self._db.get_tx_by_neon_sig(neon_sig)
        if neon_tx_receipt is None:
            neon_tx: Union[NeonTx, EthereumError, None] = self._mempool_client.get_pending_tx_by_hash(
                get_req_id_from_log(), neon_sig)
            if neon_tx is None:
                LOG.debug("Not found receipt")
                return None
            elif isinstance(neon_tx, EthereumError):
                raise neon_tx

            neon_tx_receipt = NeonTxReceiptInfo(NeonTxInfo.from_neon_tx(neon_tx), NeonTxResultInfo())
        return self._get_transaction(neon_tx_receipt)

    def eth_getCode(self, account: str, tag: Union[str, int]) -> str:
        self._validate_block_tag(tag)
        account = self._normalize_address(account)

        try:
            account_info = self._solana.get_neon_account_info(account)
            if (not account_info) or (not account_info.code):
                return '0x'

            return account_info.code
        except (Exception,):
            return '0x'

    def eth_sendRawTransaction(self, raw_tx: str) -> str:
        try:
            neon_tx = NeonTx.from_string(bytearray.fromhex(raw_tx[2:]))
        except (Exception,):
            raise InvalidParamError(message="wrong transaction format")

        def _readable_tx(tx: NeonTx) -> dict:
            result = dict()
            for k, v in tx.as_dict().items():
                if isinstance(v, bytearray) or isinstance(v, bytes):
                    result[k] = v.hex()
                else:
                    result[k] = v
            return result

        neon_tx_sig = neon_tx.hex_tx_sig
        LOG.debug(f'sendRawTransaction {neon_tx_sig}: {_readable_tx(neon_tx)}')

        try:
            neon_tx_receipt: NeonTxReceiptInfo = self._db.get_tx_by_neon_sig(neon_tx_sig)
            if neon_tx_receipt is not None:
                raise EthereumError(message='already known')

            min_gas_price = self._gas_price.min_gas_price
            neon_tx_validator = NeonTxValidator(self._config, self._solana, neon_tx, min_gas_price)
            neon_tx_exec_cfg = neon_tx_validator.precheck()

            result: MPTxSendResult = self._mempool_client.send_raw_transaction(
                req_id=get_req_id_from_log(), neon_sig=neon_tx_sig, neon_tx=neon_tx, neon_tx_exec_cfg=neon_tx_exec_cfg
            )

            if result.code in (MPTxSendResultCode.Success, MPTxSendResultCode.AlreadyKnown):
                return neon_tx_sig
            elif result.code == MPTxSendResultCode.Underprice:
                raise EthereumError(message='replacement transaction underpriced')
            elif result.code == MPTxSendResultCode.NonceTooLow:
                neon_tx_validator.raise_nonce_error(result.state_tx_cnt, neon_tx.nonce)
            else:
                raise EthereumError(message='unknown error')
        except EthereumError:
            raise

        except BaseException as exc:
            LOG.error('Failed to process eth_sendRawTransaction.', exc_info=exc)
            raise

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

    def eth_getTransactionByBlockNumberAndIndex(self, tag: str, tx_idx: int) -> Optional[Dict[str, Any]]:
        block = self._process_block_tag(tag)
        return self._get_transaction_by_index(block, tx_idx)

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
        sender = self._normalize_address(sender)

        if 'to' in tx:
            tx['to'] = self._normalize_address(tx['to'])

        account = KeyStorage().get_key(sender)
        if not account:
            raise EthereumError(message='unknown account')

        if 'nonce' not in tx:
            tx['nonce'] = self.eth_getTransactionCount(sender, 'pending')

        if 'chainId' not in tx:
            tx['chainId'] = hex(ElfParams().chain_id)

        try:
            signed_tx = NeonAccount().sign_transaction(tx, account.private)
            raw_tx = signed_tx.rawTransaction.hex()
            neon_tx = NeonTx.from_string(bytearray.fromhex(raw_tx[2:]))

            tx['from'] = neon_tx.hex_sender
            tx['to'] = neon_tx.hex_to_address
            tx['hash'] = neon_tx.hex_tx_sig
            tx['r'] = hex(neon_tx.r)
            tx['s'] = hex(neon_tx.s)
            tx['v'] = hex(neon_tx.v)

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

        return keccak_256(data).hexdigest()

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
            latest_slot = self._db.get_latest_block_slot()
            first_slot = self._db.get_starting_block_slot()

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

    def neon_getSolanaTransactionByNeonTransaction(self, neon_tx_id: str) -> Union[str, list]:
        neon_sig = self._normalize_tx_id(neon_tx_id)
        return self._db.get_sol_sig_list_by_neon_sig(neon_sig)

    def neon_emulate(self, raw_signed_tx: str):
        """Executes emulator with given transaction
        """
        LOG.debug(f"Call neon_emulate: {raw_signed_tx}")

        neon_tx = NeonTx.from_string(bytearray.fromhex(raw_signed_tx))
        emulation_result = call_tx_emulated(self._config, neon_tx)
        return emulation_result

    def neon_finalizedBlockNumber(self) -> str:
        slot = self._db.get_finalized_block_slot()
        return hex(slot)

    @staticmethod
    def neon_getEvmParams() -> Dict[str, str]:
        """Returns map of Neon-EVM parameters"""
        return ElfParams().elf_param_dict

    def is_allowed_api(self, method_name: str) -> bool:
        for prefix in ('eth_', 'net_', 'web3_', 'neon_'):
            if method_name.startswith(prefix):
                break
        else:
            return False

        if method_name in {'neon_proxy_version', 'neon_proxyVersion'}:
            return True

        now = math.ceil(time.time())
        elf_params = ElfParams()
        if self._last_elf_params_time != now:
            elf_param_dict = self._mempool_client.get_elf_param_dict(get_req_id_from_log())
            if elf_param_dict is None:
                raise EthereumError(message='Failed to read Neon EVM params from Solana cluster. Try again later')
            elf_params.set_elf_param_dict(elf_param_dict)

        always_allowed_method_set = {
            "eth_chainId",
            "neon_cliVersion",
            "neon_cli_version",
            "neon_getEvmParams"
            "net_version",
            "web3_clientVersion"
        }

        if method_name in always_allowed_method_set:
            if elf_params.has_params():
                return True

        if not elf_params.is_evm_compatible(NEON_PROXY_PKG_VERSION):
            raise EthereumError(
                f'Neon Proxy {self.neon_proxy_version()} is not compatible with '
                f'Neon EVM {self.web3_clientVersion()}'
            )

        if method_name == 'eth_sendRawTransaction':
            return self._config.enable_send_tx_api

        private_method_set = {
            "eth_accounts",
            "eth_sign",
            "eth_sendTransaction",
            "eth_signTransaction",
        }

        if method_name in private_method_set:
            if (not self._config.enable_send_tx_api) or (not self._config.enable_private_api):
                return False

        return True
