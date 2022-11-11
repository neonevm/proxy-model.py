import json
import math
import multiprocessing
import time

from typing import Optional, Union, Dict, Any, List, cast

import eth_utils
import sha3

from logged_groups import logged_group, LogMng
from eth_account import Account as NeonAccount

from ..common_neon.address import NeonAddress
from ..common_neon.config import Config
from ..common_neon.elf_params import ElfParams
from ..common_neon.emulator_interactor import call_emulated, check_emulated_exit_status, call_tx_emulated
from ..common_neon.environment_utils import NeonCli
from ..common_neon.errors import EthereumError, InvalidParamError
from ..common_neon.estimate import GasEstimate
from ..common_neon.eth_proto import NeonTx
from ..common_neon.keys_storage import KeyStorage
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.transaction_validator import NeonTxValidator
from ..common_neon.utils import JsonBytesEncoder
from ..common_neon.utils import SolanaBlockInfo, NeonTxReceiptInfo, NeonTxInfo, NeonTxResultInfo

from ..indexer.indexer_db import IndexerDB

from ..mempool import MemPoolClient, MP_SERVICE_ADDR, MPTxSendResult, MPTxSendResultCode, MPGasPriceResult

NEON_PROXY_PKG_VERSION = '0.13.0-dev'
NEON_PROXY_REVISION = 'NEON_PROXY_REVISION_TO_BE_REPLACED'


@logged_group("neon.Proxy")
class NeonRpcApiWorker:
    proxy_id_glob = multiprocessing.Value('i', 0)

    def __init__(self, config: Config):
        self._config = config
        self._solana = SolInteractor(self._config, self._config.solana_url)
        self._db = IndexerDB()
        self._mempool_client = MemPoolClient(MP_SERVICE_ADDR)

        self._gas_price_value: Optional[MPGasPriceResult] = None
        self._last_gas_price_time = 0

        self._last_elf_params_time = 0

        with self.proxy_id_glob.get_lock():
            self.proxy_id = self.proxy_id_glob.value
            self.proxy_id_glob.value += 1

        if self.proxy_id == 0:
            self.debug(f'Neon Proxy version: {self.neon_proxy_version()}')
        self.debug(f"Worker id {self.proxy_id}")

    @property
    def _gas_price(self) -> MPGasPriceResult:
        now = math.ceil(time.time())
        if self._last_gas_price_time != now:
            req_id = LogMng.get_logging_context().get("req_id")
            gas_price = self._mempool_client.get_gas_price(req_id)
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
            param['from'] = self._normalize_account(param['from'])
        if 'to' in param:
            param['to'] = self._normalize_account(param['to'])

        try:
            calculator = GasEstimate(self._config, self._solana, param)
            calculator.execute()
            return hex(calculator.estimate())

        except EthereumError:
            raise
        except BaseException as exc:
            self.debug(f"Exception on eth_estimateGas: {str(exc)}")
            raise

    def __repr__(self):
        return str(self.__dict__)

    def _should_return_starting_block(self, tag: Union[str, int]) -> bool:
        return tag == 'earliest' \
            or ((tag == '0x0' or str(tag) == '0') and self._config.use_earliest_block_if_0_passed)

    def _process_block_tag(self, tag: Union[str, int]) -> SolanaBlockInfo:
        if tag == 'latest':
            block = self._db.get_latest_block()
        elif tag == 'pending':
            latest_block = self._db.get_latest_block()
            block = SolanaBlockInfo(
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
                block = SolanaBlockInfo(block_slot=int(tag.strip(), 16))
            except (Exception,):
                raise InvalidParamError(message=f'failed to parse block tag: {tag}')
        elif isinstance(tag, int):
            block = SolanaBlockInfo(block_slot=tag)
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

    @staticmethod
    def _validate_block_tag(tag: Union[int, str]) -> None:
        if isinstance(tag, int):
            return

        try:
            tag.strip().lower()
            if tag in {'latest', 'pending', 'earliest', 'finalized', 'safe'}:
                return

            assert tag[:2] == '0x'
            int(tag[2:], 16)
        except (Exception,):
            raise InvalidParamError(message=f'invalid block tag {tag}')

    @staticmethod
    def _normalize_account(account: str) -> str:
        try:
            sender = account.strip().lower()
            assert sender[:2] == '0x'
            sender = sender[2:]

            bin_sender = bytes.fromhex(sender)
            assert len(bin_sender) == 20

            return eth_utils.to_checksum_address(sender)
        except (Exception,):
            raise InvalidParamError(message='bad account')

    def _get_full_block_by_number(self, tag: Union[str, int]) -> SolanaBlockInfo:
        block = self._process_block_tag(tag)
        if block.is_empty():
            block = self._db.get_block_by_slot(block.block_slot)
            if block.is_empty():
                self.debug(f"Not found block by slot {block.block_slot}")

        return block

    def eth_blockNumber(self) -> str:
        slot = self._db.get_latest_block_slot()
        return hex(slot)

    def eth_getBalance(self, account: str, tag: Union[int, str]) -> str:
        """account - address to check for balance.
           tag - integer block number, or the string "finalized", "safe", "latest", "earliest" or "pending"
        """

        self._validate_block_tag(tag)
        account = self._normalize_account(account)

        try:
            if tag == 'pending':
                commitment = 'processed'
            elif tag in {'finalized', 'safe'}:
                commitment = 'finalized'
            else:
                commitment = 'confirmed'

            neon_account_info = self._solana.get_neon_account_info(NeonAddress(account), commitment)
            if neon_account_info is None:
                return hex(0)

            return hex(neon_account_info.balance)
        except (Exception,):
            # self.debug(f"eth_getBalance: Can't get account info: {err}")
            return hex(0)

    def eth_getLogs(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        def to_list(items):
            if isinstance(items, str):
                return [items.lower()]
            elif isinstance(items, list):
                return list(set([item.lower() for item in items if isinstance(item, str)]))
            return []

        from_block = None
        to_block = None
        addresses = []
        topics = []
        block_hash = None

        if 'fromBlock' in obj and obj['fromBlock'] != '0':
            from_block = self._process_block_tag(obj['fromBlock']).block_slot
        if 'toBlock' in obj and obj['toBlock'] not in {'latest', 'pending', 'finalized', 'safe'}:
            to_block = self._process_block_tag(obj['toBlock']).block_slot
        if 'address' in obj:
            addresses = to_list(obj['address'])
        if 'topics' in obj:
            topics = to_list(obj['topics'])
        if 'blockHash' in obj:
            block_hash = obj['blockHash']

        return self._db.get_logs(from_block, to_block, addresses, topics, block_hash)

    def _get_block_by_slot(self, block: SolanaBlockInfo, full: bool, skip_transaction: bool) -> Optional[dict]:
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
            gas_used += int(tx.neon_tx_res.gas_used, 16)

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
        account = self._normalize_account(account)

        try:
            value = NeonCli(self._config).call('get-storage-at', account, position)
            return value
        except (Exception,):
            # self.error(f"eth_getStorageAt: Neon-cli failed to execute: {err}")
            return '0x00'

    def _get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        try:
            block_hash = block_hash.strip().lower()
            assert block_hash[:2] == '0x'

            bin_block_hash = bytes.fromhex(block_hash[2:])
            assert len(bin_block_hash) == 32
        except (Exception,):
            raise InvalidParamError(message=f'bad block hash {block_hash}')

        block = self._db.get_block_by_hash(block_hash)
        if block.is_empty():
            self.debug("Not found block by hash %s", block_hash)

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
            emulator_json = call_emulated(self._config, contract_id, caller_id, data, value)
            check_emulated_exit_status(emulator_json)
            return '0x' + emulator_json['result']
        except EthereumError:
            raise
        except Exception as err:
            self.debug(f'eth_call Exception {err}.')
            raise

    def eth_getTransactionCount(self, account: str, tag: Union[str, int]) -> str:
        self._validate_block_tag(tag)
        account = self._normalize_account(account).lower()

        try:
            self.debug(f'Get transaction count. Account: {account}, tag: {tag}')

            pending_tx_nonce: Optional[int] = None
            commitment = 'confirmed'

            if tag == 'pending':
                commitment = 'processed'

                req_id = LogMng.get_logging_context().get('req_id')
                pending_tx_nonce = self._mempool_client.get_pending_tx_nonce(req_id=req_id, sender=account)
                self.debug(f'Pending tx count for: {account} - is: {pending_tx_nonce}')
            elif tag == 'latest':
                commitment = 'processed'

                req_id = LogMng.get_logging_context().get('req_id')
                pending_tx_nonce = self._mempool_client.get_mempool_tx_nonce(req_id=req_id, sender=account)
                self.debug(f'Mempool tx count for: {account} - is: {pending_tx_nonce}')
            elif tag in {'finalized', 'safe'}:
                commitment = 'finalized'

            if pending_tx_nonce is None:
                pending_tx_nonce = 0

            neon_account_info = self._solana.get_neon_account_info(account, commitment)
            tx_count = max(neon_account_info.tx_count, pending_tx_nonce)

            return hex(tx_count)
        except (Exception,):
            # self.debug(f"eth_getTransactionCount: Can't get account info: {err}")
            return hex(0)

    @staticmethod
    def _get_transaction_receipt(tx: NeonTxReceiptInfo) -> dict:
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
            "logs": tx.neon_tx_res.log_list,
            "status": tx.neon_tx_res.status,
            "logsBloom": "0x"+'0'*512
        }

        return result

    def eth_getTransactionReceipt(self, neon_tx_sig: str) -> Optional[dict]:
        neon_sig = self._normalize_tx_id(neon_tx_sig)

        tx = self._db.get_tx_by_neon_sig(neon_sig)
        if not tx:
            req_id = LogMng.get_logging_context().get("req_id")
            neon_tx_or_error = self._mempool_client.get_pending_tx_by_hash(req_id, neon_tx_sig)
            if isinstance(neon_tx_or_error, EthereumError):
                raise neon_tx_or_error
            return None
        return self._get_transaction_receipt(tx)

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
            req_id = LogMng.get_logging_context().get("req_id")
            neon_tx: Union[NeonTx, EthereumError, None] = self._mempool_client.get_pending_tx_by_hash(req_id, neon_sig)
            if neon_tx is None:
                self.debug("Not found receipt")
                return None
            elif isinstance(neon_tx, EthereumError):
                raise neon_tx

            neon_tx_receipt = NeonTxReceiptInfo(NeonTxInfo.from_neon_tx(neon_tx), NeonTxResultInfo())
        return self._get_transaction(neon_tx_receipt)

    def eth_getCode(self, account: str, tag: Union[str, int]) -> str:
        self._validate_block_tag(tag)
        account = self._normalize_account(account)

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

        neon_sig = '0x' + neon_tx.hash_signed().hex()
        self.debug(f"sendRawTransaction {neon_sig}: {json.dumps(neon_tx.as_dict(), cls=JsonBytesEncoder)}")

        try:
            neon_tx_receipt: NeonTxReceiptInfo = self._db.get_tx_by_neon_sig(neon_sig)
            if neon_tx_receipt is not None:
                raise EthereumError(message='already known')

            min_gas_price = self._gas_price.min_gas_price
            neon_tx_validator = NeonTxValidator(self._config, self._solana, neon_tx, min_gas_price)
            neon_tx_exec_cfg = neon_tx_validator.precheck()

            req_id = LogMng.get_logging_context().get("req_id")

            result: MPTxSendResult = self._mempool_client.send_raw_transaction(
                req_id=req_id, neon_sig=neon_sig, neon_tx=neon_tx, neon_tx_exec_cfg=neon_tx_exec_cfg
            )

            if result.code in (MPTxSendResultCode.Success, MPTxSendResultCode.AlreadyKnown):
                return neon_sig
            elif result.code == MPTxSendResultCode.Underprice:
                raise EthereumError(message='replacement transaction underpriced')
            elif result.code == MPTxSendResultCode.NonceTooLow:
                neon_tx_validator.raise_nonce_error(result.state_tx_cnt, neon_tx.nonce)
            else:
                raise EthereumError(message='unknown error')
        except EthereumError:
            raise

        except BaseException as exc:
            self.error('Failed to process eth_sendRawTransaction.', exc_info=exc)
            raise

    def _get_transaction_by_index(self, block: SolanaBlockInfo, tx_idx: Union[str, int]) -> Optional[Dict[str, Any]]:
        try:
            if isinstance(tx_idx, str):
                tx_idx = int(tx_idx, 16)
            assert tx_idx >= 0
        except (Exception,):
            raise EthereumError(message=f'invalid transaction index {tx_idx}')

        if block.is_empty():
            block = self._db.get_block_by_slot(block.block_slot)
            if block.is_empty():
                self.debug(f"Not found block by slot {block.block_slot}")
                return None

        neon_tx_receipt = self._db.get_tx_by_block_slot_tx_idx(block.block_slot, tx_idx)
        if neon_tx_receipt is None:
            self.debug("Not found receipt")
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
                self.debug(f"Not found block by slot {block.block_slot}")
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
        address = self._normalize_account(address)
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
        sender = self._normalize_account(sender)

        if 'to' in tx:
            tx['to'] = self._normalize_account(tx['to'])

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

            tx['from'] = sender
            tx['to'] = NeonTx.from_string(bytearray.fromhex(raw_tx[2:])).toAddress.hex()
            tx['hash'] = signed_tx.hash.hex()
            tx['r'] = hex(signed_tx.r)
            tx['s'] = hex(signed_tx.s)
            tx['v'] = hex(signed_tx.v)

            return {
                'raw': raw_tx,
                'tx': tx
            }
        except BaseException as exc:
            self.error('Failed on sign transaction.', exc_info=exc)
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

        return sha3.keccak_256(data).hexdigest()

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

            self.debug(f'slots_behind: {slots_behind}, latest_slot: {latest_slot}, first_slot: {first_slot}')
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
        self.debug(f"Call neon_emulate: {raw_signed_tx}")

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
            req_id = LogMng.get_logging_context().get("req_id")
            elf_param_dict = self._mempool_client.get_elf_param_dict(req_id)
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
