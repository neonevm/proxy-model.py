import math
import os

from decimal import Decimal
from typing import Optional
from urllib.parse import urlparse
from typing import Optional, Set

from .db.db_config import DBConfig
from .environment_data import EVM_LOADER_ID
from .solana_tx import SolPubKey, SolCommit


def parse_solana_websocket_url(solana_url: str) -> str:
    parsed_solana_url = urlparse(solana_url)
    scheme = "wss" if parsed_solana_url.scheme == "https" else "ws"

    if parsed_solana_url.port is not None:
        port = parsed_solana_url.port + 1
        netloc = f"{parsed_solana_url.hostname}:{port}"
    else:
        netloc = parsed_solana_url.netloc

    parsed_solana_websocket_url = parsed_solana_url._replace(
        scheme=scheme,
        netloc=netloc)

    return parsed_solana_websocket_url.geturl()


class Config(DBConfig):
    _one_block_sec = 0.4
    _min_finalize_sec = _one_block_sec * 32

    def __init__(self):
        super().__init__()
        self._solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
        self._solana_websocket_url = parse_solana_websocket_url(self._solana_url)
        self._pp_solana_url = os.environ.get("PP_SOLANA_URL", self._solana_url)
        self._evm_program_id = SolPubKey.from_string(EVM_LOADER_ID)
        self._mempool_capacity = self._env_int("MEMPOOL_CAPACITY", 10, 4096)
        self._mempool_executor_limit_cnt = self._env_int('MEMPOOL_EXECUTOR_LIMIT_CNT', 4, 1024)
        self._mempool_cache_life_sec = self._env_int('MEMPOOL_CACHE_LIFE_SEC', 15, 30 * 60)
        self._accept_reverted_tx_into_mempool = self._env_bool('ACCEPT_REVERTED_TX_INTO_MEMPOOL', False)
        self._holder_size = self._env_int("HOLDER_SIZE", 1024, 262144)  # 256*1024
        self._min_op_balance_to_warn = self._env_int("MIN_OPERATOR_BALANCE_TO_WARN", 9000000000, 9000000000)
        self._min_op_balance_to_err = self._env_int("MIN_OPERATOR_BALANCE_TO_ERR", 1000000000, 1000000000)
        self._perm_account_id = self._env_int("PERM_ACCOUNT_ID", 1, 1)
        self._perm_account_limit = self._env_int("PERM_ACCOUNT_LIMIT", 1, 2)
        self._recheck_used_resource_sec = self._env_int('RECHECK_USED_RESOURCE_SEC', 10, 60)
        self._recheck_resource_after_uses_cnt = self._env_int("RECHECK_RESOURCE_AFTER_USES_CNT", 10, 60)
        self._retry_on_fail = self._env_int("RETRY_ON_FAIL", 1, 10)
        self._enable_private_api = self._env_bool("ENABLE_PRIVATE_API", False)
        self._enable_send_tx_api = self._env_bool("ENABLE_SEND_TX_API", True)
        self._use_earliest_block_if_0_passed = self._env_bool("USE_EARLIEST_BLOCK_IF_0_PASSED", False)
        self._account_permission_update_int = self._env_int("ACCOUNT_PERMISSION_UPDATE_INT", 10, 60 * 5)
        self._allow_underpriced_tx_wo_chainid = self._env_bool('ALLOW_UNDERPRICED_TX_WITHOUT_CHAINID', False)
        self._operator_fee = self._env_decimal('OPERATOR_FEE', "0.1")
        self._gas_price_slippage = self._env_decimal('GAS_PRICE_SLIPPAGE', "0.01")
        self._slot_processing_delay = self._env_int("SLOT_PROCESSING_DELAY", 0, 0)
        self._min_gas_price = self._env_int("MINIMAL_GAS_PRICE", 0, 1) * (10 ** 9)
        self._min_wo_chainid_gas_price = self._env_int("MINIMAL_WO_CHAINID_GAS_PRICE", 0, 10) * (10 ** 9)
        self._gas_less_tx_max_nonce = self._env_int("GAS_LESS_MAX_TX_NONCE", 0, 5)
        self._gas_less_tx_max_gas = self._env_int("GAS_LESS_MAX_GAS", 0, 20_000_000)  # Estimated gas on Mora = 18 mln
        self._neon_price_usd = Decimal('0.25')
        self._start_slot = os.environ.get('START_SLOT', '0')
        self._gas_tank_parallel_request_cnt = self._env_int("GAS_TANK_PARALLEL_REQUEST_COUNT", 1, 10)
        self._gas_tank_poll_tx_cnt = self._env_int('GAS_TANK_POLL_TX_COUNT', 1, 1000)
        self._indexer_poll_block_cnt = self._env_int('INDEXER_POLL_BLOCK_COUNT', 1, 32)
        self._indexer_check_msec = self._env_int('INDEXER_CHECK_MSEC', 50, 200)
        self._metrics_log_skip_cnt = self._env_int('METRICS_LOG_SKIP_COUNT', 1, 1000)
        self._max_tx_account_cnt = self._env_int("MAX_TX_ACCOUNT_COUNT", 20, 62)
        self._fuzz_fail_pct = self._env_int("FUZZ_FAIL_PCT", 0, 0)
        self._confirm_timeout_sec = self._env_int("CONFIRM_TIMEOUT_SEC", 4, math.ceil(self._min_finalize_sec))
        self._max_evm_step_cnt_emulate = self._env_int("MAX_EVM_STEP_COUNT_TO_EMULATE", 1000, 500000)
        self._neon_cli_timeout = self._env_decimal("NEON_CLI_TIMEOUT", "2.5")
        self._neon_cli_debug_log = self._env_bool("NEON_CLI_DEBUG_LOG", False)
        self._stuck_obj_blockout = self._env_int('STUCK_OBJECT_BLOCKOUT', 16, 64)
        self._stuck_obj_validate_blockout = self._env_int('STUCK_OBJECT_VALIDATE_BLOCKOUT', 512, 1024)
        self._alt_freeing_depth = self._env_int('ALT_FREEING_DEPTH', 512, 512 + 16)
        self._gather_statistics = self._env_bool("GATHER_STATISTICS", False)
        self._hvac_url = os.environ.get('HVAC_URL', None)
        self._hvac_token = os.environ.get('HVAC_TOKEN', None)
        self._hvac_mount = os.environ.get('HVAC_MOUNT', None)
        self._hvac_path = os.environ.get('HVAC_PATH', '')
        self._genesis_timestamp = self._env_int('GENESIS_BLOCK_TIMESTAMP', 0, 0)
        self._commit_level = os.environ.get('COMMIT_LEVEL', SolCommit.Confirmed)
        self._ch_dsn_list = os.environ.get('CLICKHOUSE_DSN_LIST', '')

        pyth_mapping_account = os.environ.get('PYTH_MAPPING_ACCOUNT', None)
        if pyth_mapping_account is not None:
            self._pyth_mapping_account = SolPubKey.from_string(pyth_mapping_account)
        else:
            self._pyth_mapping_account = None
        self._update_pyth_mapping_period_sec = self._env_int('UPDATE_PYTH_MAPPING_PERIOD_SEC', 10, 60 * 60)

        op_acct_list = os.environ.get('OPERATOR_ACCOUNT_LIST', '')
        self._op_acct_set = set([acct for acct in op_acct_list.split(' ;,') if len(acct) > 0])

        self._validate()

    def _validate(self) -> None:
        self._commit_level = SolCommit.Type(self._commit_level.lower())
        assert SolCommit.level(self._commit_level) >= SolCommit.level(SolCommit.Confirmed)

        assert (self._operator_fee > 0) and (self._operator_fee <= 1)
        assert (self._gas_price_slippage >= 0) and (self._gas_price_slippage < 1)
        assert (self._slot_processing_delay < 32)
        assert (self._fuzz_fail_pct >= 0) and (self._fuzz_fail_pct < 100)

        for acct in self._op_acct_set:
            pubkey = SolPubKey.from_string(acct)
            assert str(pubkey) == acct, f'Invalid operator account {acct}'

    @staticmethod
    def _env_bool(name: str, default_value: bool) -> bool:
        return os.environ.get(name, "YES" if default_value else "NO") == "YES"

    @staticmethod
    def _env_int(name: str, min_value: int, default_value: int) -> int:
        return max(int(os.environ.get(name, str(default_value))), min_value)

    @staticmethod
    def _env_decimal(name: str, default_value: str) -> Decimal:
        return Decimal(os.environ.get(name, default_value))

    @property
    def one_block_sec(self) -> float:
        return self._one_block_sec

    @property
    def min_finalize_sec(self) -> float:
        return self._min_finalize_sec

    @property
    def solana_url(self) -> str:
        return self._solana_url

    @property
    def solana_websocket_url(self) -> str:
        return self._solana_websocket_url

    @property
    def mempool_capacity(self) -> int:
        return self._mempool_capacity

    @property
    def mempool_executor_limit_cnt(self) -> int:
        return self._mempool_executor_limit_cnt

    @property
    def mempool_cache_life_sec(self) -> int:
        return self._mempool_cache_life_sec

    @property
    def accept_reverted_tx_into_mempool(self) -> bool:
        return self._accept_reverted_tx_into_mempool

    @property
    def pyth_mapping_account(self) -> Optional[SolPubKey]:
        return self._pyth_mapping_account

    @property
    def update_pyth_mapping_period_sec(self) -> int:
        return self._update_pyth_mapping_period_sec

    @property
    def pyth_solana_url(self) -> str:
        return self._pp_solana_url

    @property
    def evm_program_id(self) -> SolPubKey:
        return self._evm_program_id

    @property
    def holder_size(self) -> int:
        return self._holder_size

    @property
    def min_operator_balance_to_warn(self) -> int:
        return self._min_op_balance_to_warn

    @property
    def min_operator_balance_to_err(self) -> int:
        return self._min_op_balance_to_err

    @property
    def perm_account_id(self) -> int:
        return self._perm_account_id

    @property
    def perm_account_limit(self) -> int:
        return self._perm_account_limit

    @property
    def recheck_used_resource_sec(self) -> int:
        return self._recheck_used_resource_sec

    @property
    def recheck_resource_after_uses_cnt(self) -> int:
        return self._recheck_resource_after_uses_cnt

    @property
    def retry_on_fail(self) -> int:
        return self._retry_on_fail

    @property
    def enable_private_api(self) -> bool:
        return self._enable_private_api

    @property
    def enable_send_tx_api(self) -> bool:
        return self._enable_send_tx_api

    @property
    def use_earliest_block_if_0_passed(self) -> bool:
        return self._use_earliest_block_if_0_passed

    @property
    def allow_underpriced_tx_wo_chainid(self) -> bool:
        return self._allow_underpriced_tx_wo_chainid

    @property
    def operator_fee(self) -> Decimal:
        return self._operator_fee

    @property
    def gas_price_slippage(self) -> Decimal:
        return self._gas_price_slippage

    @property
    def slot_processing_delay(self) -> int:
        """Slot processing delay relative to the last confirmed slot on Tracer API node"""
        return self._slot_processing_delay

    @property
    def min_gas_price(self) -> int:
        """Minimal gas price to accept tx into the mempool"""
        return self._min_gas_price

    @property
    def min_wo_chainid_gas_price(self) -> int:
        """Minimal gas price for txs without chain-id"""
        return self._min_wo_chainid_gas_price

    @property
    def gas_less_tx_max_nonce(self) -> int:
        return self._gas_less_tx_max_nonce

    @property
    def gas_less_tx_max_gas(self) -> int:
        return self._gas_less_tx_max_gas

    @property
    def neon_price_usd(self) -> Decimal:
        return self._neon_price_usd

    @property
    def start_slot(self) -> str:
        return self._start_slot

    @property
    def gas_tank_parallel_request_cnt(self) -> int:
        return self._gas_tank_parallel_request_cnt

    @property
    def gas_tank_poll_tx_cnt(self) -> int:
        return self._gas_tank_poll_tx_cnt

    @property
    def indexer_poll_block_cnt(self) -> int:
        return self._indexer_poll_block_cnt

    @property
    def indexer_check_msec(self) -> int:
        return self._indexer_check_msec

    @property
    def metrics_log_skip_cnt(self) -> int:
        return self._metrics_log_skip_cnt

    @property
    def max_tx_account_cnt(self) -> int:
        return self._max_tx_account_cnt

    @property
    def fuzz_fail_pct(self) -> int:
        return self._fuzz_fail_pct

    @property
    def confirm_timeout_sec(self) -> int:
        return self._confirm_timeout_sec

    @property
    def max_evm_step_cnt_emulate(self) -> int:
        return self._max_evm_step_cnt_emulate

    @property
    def neon_cli_timeout(self) -> float:
        return float(self._neon_cli_timeout)

    @property
    def neon_cli_debug_log(self) -> bool:
        return self._neon_cli_debug_log

    @property
    def stuck_object_blockout(self) -> int:
        return self._stuck_obj_blockout

    @property
    def stuck_object_validate_blockout(self) -> int:
        return self._stuck_obj_validate_blockout

    @property
    def alt_freeing_depth(self) -> int:
        return self._alt_freeing_depth

    @property
    def operator_account_set(self) -> Set[str]:
        return self._op_acct_set

    @property
    def gather_statistics(self) -> bool:
        return self._gather_statistics

    @property
    def hvac_url(self) -> Optional[str]:
        return self._hvac_url

    @property
    def hvac_token(self) -> Optional[str]:
        return self._hvac_token

    @property
    def hvac_mount(self) -> Optional[str]:
        return self._hvac_mount

    @property
    def hvac_path(self) -> str:
        return self._hvac_path

    @property
    def genesis_timestamp(self) -> int:
        return self._genesis_timestamp

    @property
    def commit_level(self) -> SolCommit.Type:
        return self._commit_level

    @property
    def ch_dsn_list(self) -> str:
        return self._ch_dsn_list

    def as_dict(self) -> dict:
        config_dict = {
            'EVM_LOADER_ID': str(self.evm_program_id),
            'PYTH_MAPPING_ACCOUNT': str(self.pyth_mapping_account),
            'UPDATE_PYTH_MAPPING_PERIOD_SEC': self.update_pyth_mapping_period_sec,
            'MEMPOOL_CAPACITY': self.mempool_capacity,
            'MEMPOOL_EXECUTOR_LIMIT_CNT': self.mempool_executor_limit_cnt,
            'MEMPOOL_CACHE_LIFE_SEC': self.mempool_cache_life_sec,
            'ACCEPT_REVERTED_TX_INTO_MEMPOOL': self.accept_reverted_tx_into_mempool,
            'HOLDER_SIZE': self.holder_size,
            'MIN_OPERATOR_BALANCE_TO_WARN': self.min_operator_balance_to_warn,
            'MIN_OPERATOR_BALANCE_TO_ERR': self.min_operator_balance_to_err,
            'PERM_ACCOUNT_ID': self.perm_account_id,
            'PERM_ACCOUNT_LIMIT': self.perm_account_limit,
            'RECHECK_USED_RESOURCE_SEC': self.recheck_used_resource_sec,
            'RECHECK_RESOURCE_AFTER_USES_CNT': self.recheck_resource_after_uses_cnt,
            'RETRY_ON_FAIL': self.retry_on_fail,
            'ENABLE_PRIVATE_API': self.enable_private_api,
            'ENABLE_SEND_TX_API': self.enable_send_tx_api,
            'USE_EARLIEST_BLOCK_IF_0_PASSED': self.use_earliest_block_if_0_passed,
            'ALLOW_UNDERPRICED_TX_WITHOUT_CHAINID': self.allow_underpriced_tx_wo_chainid,
            'OPERATOR_FEE': self.operator_fee,
            'SLOT_PROCESSING_DELAY': self.slot_processing_delay,
            'GAS_PRICE_SLIPPAGE': self.gas_price_slippage,
            'MINIMAL_GAS_PRICE': self.min_gas_price,
            'MINIMAL_WO_CHAINID_GAS_PRICE': self.min_wo_chainid_gas_price,
            'GAS_LESS_MAX_TX_NONCE': self.gas_less_tx_max_nonce,
            'GAS_LESS_MAX_GAS': self.gas_less_tx_max_gas,
            'NEON_PRICE_USD': self.neon_price_usd,
            'START_SLOT': self.start_slot,
            'GAS_TANK_PARALLEL_REQUEST_COUNT': self.gas_tank_parallel_request_cnt,
            'GAS_TANK_POLL_TX_COUNT': self.gas_tank_poll_tx_cnt,
            'INDEXER_POLL_BLOCK_COUNT': self.indexer_poll_block_cnt,
            'INDEXER_CHECK_MSEC': self.indexer_check_msec,
            'METRICS_LOG_SKIP_COUNT': self.metrics_log_skip_cnt,
            'MAX_TX_ACCOUNT_COUNT': self.max_tx_account_cnt,
            'FUZZ_FAIL_PCT': self.fuzz_fail_pct,
            'CONFIRM_TIMEOUT_SEC': self.confirm_timeout_sec,
            'MAX_EVM_STEP_COUNT_TO_EMULATE': self.max_evm_step_cnt_emulate,
            'NEON_CLI_TIMEOUT': self.neon_cli_timeout,
            'NEON_CLI_DEBUG_LOG': self.neon_cli_debug_log,
            'STUCK_OBJECT_BLOCKOUT': self.stuck_object_blockout,
            'STUCK_OBJECT_VALIDATE_BLOCKOUT': self.stuck_object_validate_blockout,
            'ALT_FREEING_DEPTH': self.alt_freeing_depth,
            'OPERATOR_ACCOUNT_LIST': ';'.join(list(self.operator_account_set)),
            'GATHER_STATISTICS': self.gather_statistics,

            'GENESIS_BLOCK_TIMESTAMP=': self.genesis_timestamp,
            'COMMIT_LEVEL': self.commit_level,

            # Don't print accesses to the logs

            # 'SOLANA_URL': self.solana_url,
            # 'PP_SOLANA_URL': self.pyth_solana_url,

            # 'HVAC_URL': self.hvac_url,
            # 'HVAC_TOKEN': self.hvac_token,
            # 'HVAC_PATH': self.hvac_path,
            # 'HVAC_MOUNT': self.hvac_mount,

            # 'CLICKHOUSE_DSN_LIST': self.ch_dsn_list,
        }
        config_dict.update(super().as_dict())
        return config_dict
