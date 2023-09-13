import os
import re
import logging

from decimal import Decimal
from urllib.parse import urlparse
from typing import Optional, Union, Set, List, Tuple, NewType

from .db.db_config import DBConfig
from .constants import EVM_PROGRAM_ID_STR, ONE_BLOCK_SEC, MIN_FINALIZE_SEC
from .solana_tx import SolPubKey, SolCommit

LOG = logging.getLogger(__name__)


class StartSlot:
    _NameType = NewType('StartSlot', str)
    Type = Union[int, _NameType]

    Continue = _NameType('CONTINUE')
    Latest = _NameType('LATEST')
    Disable = _NameType('DISABLE')

    @staticmethod
    def to_type(value: Union[str, int]) -> Type:
        if isinstance(value, int):
            return value

        value = StartSlot._NameType(value.upper())
        if value in (StartSlot.Continue, StartSlot.Latest, StartSlot.Disable):
            return value
        return int(value)


def parse_solana_ws_url(solana_url: str) -> str:
    parsed_solana_url = urlparse(solana_url)
    scheme = 'wss' if parsed_solana_url.scheme == 'https' else 'ws'

    if parsed_solana_url.port is not None:
        port = parsed_solana_url.port + 1
        netloc = f'{parsed_solana_url.hostname}:{port}'
    else:
        netloc = parsed_solana_url.netloc

    parsed_solana_ws_url = parsed_solana_url._replace(
        scheme=scheme,
        netloc=netloc
    )

    return parsed_solana_ws_url.geturl()


class Config(DBConfig):
    start_slot_name = 'START_SLOT'
    reindex_start_slot_name = 'REINDEX_START_SLOT'
    reindex_thread_cnt_name = 'REINDEX_THREAD_COUNT'

    def __init__(self):
        super().__init__()
        self._solana_url = os.environ.get('SOLANA_URL', 'http://localhost:8899')
        self._solana_timeout = self._env_num('SOLANA_TIMEOUT', Decimal('15.0'), Decimal('1.0'), Decimal('3600'))
        self._solana_ws_url = os.environ.get('SOLANA_WS_URL', parse_solana_ws_url(self._solana_url))
        self._hide_solana_url = self._env_bool('HIDE_SOLANA_URL', True)

        self._enable_private_api = self._env_bool('ENABLE_PRIVATE_API', False)
        self._enable_send_tx_api = self._env_bool('ENABLE_SEND_TX_API', True)
        self._use_earliest_block_if_0_passed = self._env_bool('USE_EARLIEST_BLOCK_IF_0_PASSED', False)
        self._neon_cli_timeout = self._env_num('NEON_CLI_TIMEOUT', Decimal('2.5'), Decimal('1'), Decimal('20'))
        self._max_evm_step_cnt_emulate = self._env_num('MAX_EVM_STEP_COUNT_TO_EMULATE', 500_000, 1000, 4_000_000)
        self._neon_cli_debug_log = self._env_bool('NEON_CLI_DEBUG_LOG', False)
        self._gather_statistics = self._env_bool('GATHER_STATISTICS', False)

        # Mempool limits
        self._mempool_capacity = self._env_num('MEMPOOL_CAPACITY', 4096, 10, 4096 * 1024)
        self._mempool_executor_limit_cnt = self._env_num('MEMPOOL_EXECUTOR_LIMIT_COUNT', 128, 4, 1024)
        self._mempool_cache_life_sec = self._env_num(
            'MEMPOOL_CACHE_LIFE_SEC',
            30 * 60,  # 30 min
            15,      # 15 sec
            60 * 60   # 1 hour
        )

        # Transaction execution settings
        self._retry_on_fail = self._env_num('RETRY_ON_FAIL', 10, 1, 50)
        self._confirm_timeout_sec = self._env_num('CONFIRM_TIMEOUT_SEC', int(MIN_FINALIZE_SEC), 4, 32)
        self._commit_type, self._commit_level = self._env_commit_level(
            'COMMIT_LEVEL',
            SolCommit.Confirmed,
            SolCommit.Confirmed
        )
        self._max_tx_account_cnt = self._env_num('MAX_TX_ACCOUNT_COUNT', 62, 20, 256)

        # Gas-Price settings
        self._pp_solana_url = os.environ.get('PP_SOLANA_URL', self._solana_url)
        self._pyth_mapping_acct = self._env_sol_acct('PYTH_MAPPING_ACCOUNT')
        self._update_pyth_mapping_period_sec = self._env_num(
            'UPDATE_PYTH_MAPPING_PERIOD_SEC',
            60 * 60,  # 1 hour
            10,  # 10 sec
            24 * 60 * 60  # 1 day
        )
        self._operator_fee = self._env_num('OPERATOR_FEE', Decimal('0.1'), Decimal('0.0'), Decimal('100.0'))
        self._gas_price_slippage = self._env_num('GAS_PRICE_SLIPPAGE', Decimal('0.1'), Decimal('0.0'), Decimal('100.0'))

        min_gas_price = self._env_num('MINIMAL_GAS_PRICE', 1, 0, 100_000_000)
        self._min_gas_price = min_gas_price * (10 ** 9)
        self._min_wo_chainid_gas_price = self._env_num('MINIMAL_WO_CHAINID_GAS_PRICE', 10, 0, 100_000_000) * (10 ** 9)
        self._allow_underpriced_tx_wo_chainid = self._env_bool('ALLOW_UNDERPRICED_TX_WITHOUT_CHAINID', False)

        self._const_gas_price = self._env_num('CONST_GAS_PRICE', -1, min_gas_price, 100_000_000) * (10 ** 9)

        # Operator resource settings
        self._holder_size = self._env_num('HOLDER_SIZE', 256 * 1024, 1024, 10 * 1024 * 1024)
        self._min_op_balance_to_warn = self._env_num('MIN_OPERATOR_BALANCE_TO_WARN', 9_000_000_000, 1)
        self._min_op_balance_to_err = self._env_num('MIN_OPERATOR_BALANCE_TO_ERR', 1_000_000_000, 1)
        self._perm_account_id = self._env_num('PERM_ACCOUNT_ID', 1, 1, 128)
        self._perm_account_limit = self._env_num('PERM_ACCOUNT_LIMIT', 2, 1, 128)
        self._recheck_used_resource_sec = self._env_num('RECHECK_USED_RESOURCE_SEC', 60, 10, 24 * 60 * 60)
        self._recheck_resource_after_uses_cnt = self._env_num('RECHECK_RESOURCE_AFTER_USES_CNT', 60, 10, 1_000_000)

        # HashiCorp Vault for operator keys
        self._hvac_url = os.environ.get('HVAC_URL', None)
        self._hvac_token = os.environ.get('HVAC_TOKEN', None)
        self._hvac_mount = os.environ.get('HVAC_MOUNT', None)
        self._hvac_path = os.environ.get('HVAC_PATH', '')

        # Indexing settings
        self._start_slot = self._env_start_slot(self.start_slot_name, StartSlot.Latest)
        self._indexer_poll_block_cnt = self._env_num('INDEXER_POLL_BLOCK_COUNT', 32, 1, 1024)
        self._indexer_check_msec = self._env_num('INDEXER_CHECK_MSEC', 200, 50, 10_000)
        self._stuck_obj_blockout = self._env_num('STUCK_OBJECT_BLOCKOUT', 64, 16, 1024)
        self._stuck_obj_validate_blockout = self._env_num('STUCK_OBJECT_VALIDATE_BLOCKOUT', 1024, 512, 1024 * 1024)
        self._alt_freeing_depth = self._env_num('ALT_FREEING_DEPTH', 512 + 16, 512, 1024)
        self._metrics_log_skip_cnt = self._env_num('METRICS_LOG_SKIP_COUNT', 1000, 1, 100_000)
        self._genesis_timestamp = self._env_num('GENESIS_BLOCK_TIMESTAMP', 0, 0)

        self._op_acct_set = self._env_sol_acct_set('OPERATOR_ACCOUNT_LIST')

        # Integration Indexer with Tracer API
        self._slot_processing_delay = self._env_num('SLOT_PROCESSING_DELAY', 0, 0, 32)
        self._ch_dsn_list = self._env_dsn_list('CLICKHOUSE_DSN_LIST')

        # Reindexing settings
        self._reindex_start_slot = self._env_start_slot(self.reindex_start_slot_name, StartSlot.Continue)
        self._reindex_thread_cnt = self._env_num(self.reindex_thread_cnt_name, 3, 0, 128)
        self._reindex_range_len = self._env_num(
            'REINDEX_BLOCK_COUNT_IN_RANGE',
            int(60 * 60 / ONE_BLOCK_SEC),      # 1  hour
            int(10 * 60 / ONE_BLOCK_SEC),      # 10 minutes
            int(24 * 60 * 60 / ONE_BLOCK_SEC)  # 1 day
        )
        self._reindex_max_range_cnt = self._env_num('REINDEX_MAX_RANGE_COUNT', 128, 1, 256)

        # Gas-less configuration
        self._gas_tank_parallel_request_cnt = self._env_num('GAS_TANK_PARALLEL_REQUEST_COUNT', 10, 1, 100)
        self._gas_tank_poll_tx_cnt = self._env_num('GAS_TANK_POLL_TX_COUNT', 1000, 1, 1000)
        self._gas_less_tx_max_nonce = self._env_num('GAS_LESS_MAX_TX_NONCE', 5, 1, 1000)
        self._gas_less_tx_max_gas = self._env_num(
            'GAS_LESS_MAX_GAS',
            20_000_000,  # Estimated gas on Mora = 18 mln
            21_000,
            1_000_000_000
        )

        # Testing settings
        self._fuzz_fail_pct = self._env_num('FUZZ_FAIL_PCT', 0, 0, 100)

    def _validate(self) -> None:
        assert (self._const_gas_price < 0) or (self._const_gas_price >= self._min_gas_price)

    @staticmethod
    def _env_commit_level(
        name: str,
        default_value: SolCommit.Type,
        min_value: Optional[SolCommit.Type] = None
    ) -> Tuple[SolCommit.Type, int]:
        default_level = SolCommit.to_level(default_value)

        value = os.environ.get(name, None)
        if value is None:
            return default_value, default_level

        try:
            value = SolCommit.to_type(value.lower())
            value_level = SolCommit.to_level(value)
            if (min_value is not None) and (value_level < SolCommit.to_level(min_value)):
                LOG.error(f'{name} cannot be less than min value {min_value}')
                return default_value, default_level

            return value, value_level
        except (BaseException,):
            LOG.error(f'Bad value for {name}, force to use default value {default_value}')
            return default_value, default_level

    @staticmethod
    def _validate_sol_acct(name: str, value: str) -> Optional[SolPubKey]:
        try:
            return SolPubKey.from_string(value)
        except (BaseException,):
            LOG.error(f'{name} contains bad Solana account {value}')
            return None

    def _env_sol_acct(self, name: str) -> Optional[SolPubKey]:
        value = os.environ.get(name, None)
        if value is None:
            return None

        return self._validate_sol_acct(name, value)

    def _env_sol_acct_set(self, name: str) -> Set[SolPubKey]:
        raw_acct_list_str = os.environ.get(name, None)
        if raw_acct_list_str is None:
            return set()

        sol_acct_set: Set[SolPubKey] = set()
        try:
            raw_acct_list = [acct for acct in re.split(r',|;|\s', raw_acct_list_str)]
            for raw_acct in raw_acct_list:
                acct = raw_acct.strip()
                if not len(acct):
                    continue

                sol_acct = self._validate_sol_acct(name, acct)
                if sol_acct is None:
                    continue

                sol_acct_set.add(sol_acct)
        except (BaseException,):
            pass
        return sol_acct_set

    @staticmethod
    def _env_dsn_list(name: str) -> List[str]:
        raw_dsn_list_str = os.environ.get(name, None)
        if raw_dsn_list_str is None:
            return list()

        dsn_list: List[str] = list()
        try:
            raw_dsn_list = re.split(r',|;|\s', raw_dsn_list_str)
            for raw_dsn in raw_dsn_list:
                dsn = raw_dsn.strip()
                if not len(dsn):
                    continue
                dsn_list.append(dsn)
        except (BaseException,):
            LOG.error(f'{name} contains bad value')

        return dsn_list

    @staticmethod
    def _env_start_slot(name: str, default_value: StartSlot.Type) -> StartSlot.Type:
        value = os.environ.get(name, None)
        if value is None:
            return default_value
        try:
            return StartSlot.to_type(value)
        except (BaseException, ):
            LOG.error(f'{name} has bad value {value}, force to the default value {default_value}')
            return default_value

    @staticmethod
    def _env_bool(name: str, default_value: bool) -> bool:
        true_value_list = ('YES', 'ON', 'TRUE')
        false_value_list = ('NO', 'OFF', 'FALSE')

        value = os.environ.get(name, true_value_list[0] if default_value else false_value_list[0]).upper().strip()
        if (value not in true_value_list) and (value not in false_value_list):
            LOG.error(f'{name} cannot be: {true_value_list} or {false_value_list}')
            return default_value

        return value in true_value_list

    @staticmethod
    def _env_num(
        name: str, default_value: Union[int, Decimal],
        min_value: Optional[Union[int, Decimal]] = None,
        max_value: Optional[Union[int, Decimal]] = None
    ) -> Union[int, Decimal]:
        value = os.environ.get(name, None)
        if value is None:
            return default_value

        try:
            if isinstance(default_value, int):
                value = int(value, base=10)
            else:
                value = Decimal(value)

            if (min_value is not None) and (value < min_value):
                LOG.error(f'{name} cannot be less than min value {min_value}')
                value = min_value
            elif (max_value is not None) and (value > max_value):
                LOG.error(f'{name} cannot be bigger than max value {max_value}')
                value = max_value
            return value

        except (BaseException, ):
            LOG.error(f'Bad value for {name}, force to use default value {default_value}')
            return default_value

    ###################
    # Base settings

    @property
    def solana_url(self) -> str:
        return self._solana_url

    @property
    def solana_timeout(self) -> float:
        return float(self._solana_timeout)

    @property
    def solana_ws_url(self) -> str:
        return self._solana_ws_url

    @property
    def hide_solana_url(self) -> bool:
        return self._hide_solana_url

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
    def neon_cli_timeout(self) -> float:
        return float(self._neon_cli_timeout)

    @property
    def max_evm_step_cnt_emulate(self) -> int:
        return self._max_evm_step_cnt_emulate

    @property
    def neon_cli_debug_log(self) -> bool:
        return self._neon_cli_debug_log

    @property
    def gather_statistics(self) -> bool:
        return self._gather_statistics

    #####################
    # Mempool settings

    @property
    def mempool_capacity(self) -> int:
        return self._mempool_capacity

    @property
    def mempool_executor_limit_cnt(self) -> int:
        return self._mempool_executor_limit_cnt

    @property
    def mempool_cache_life_sec(self) -> int:
        return self._mempool_cache_life_sec

    #################################
    # Transaction execution settings

    @property
    def retry_on_fail(self) -> int:
        return self._retry_on_fail

    @property
    def confirm_timeout_sec(self) -> int:
        return self._confirm_timeout_sec

    @property
    def commit_level(self) -> int:
        return self._commit_level

    @property
    def commit_type(self) -> SolCommit.Type:
        return self._commit_type

    @property
    def max_tx_account_cnt(self) -> int:
        return self._max_tx_account_cnt

    #####################
    # Gas-Price settings

    @property
    def pyth_solana_url(self) -> str:
        return self._pp_solana_url

    @property
    def pyth_mapping_account(self) -> Optional[SolPubKey]:
        return self._pyth_mapping_acct

    @property
    def update_pyth_mapping_period_sec(self) -> int:
        return self._update_pyth_mapping_period_sec

    @property
    def operator_fee(self) -> Decimal:
        return self._operator_fee

    @property
    def gas_price_slippage(self) -> Decimal:
        return self._gas_price_slippage

    @property
    def min_gas_price(self) -> int:
        """Minimal gas price to accept tx into the mempool"""
        return self._min_gas_price

    @property
    def min_wo_chainid_gas_price(self) -> int:
        """Minimal gas price for txs without chain-id"""
        return self._min_wo_chainid_gas_price

    @property
    def const_gas_price(self) -> Optional[int]:
        if self._const_gas_price < 0:
            return None
        return self._const_gas_price

    @property
    def allow_underpriced_tx_wo_chainid(self) -> bool:
        return self._allow_underpriced_tx_wo_chainid

    #############################
    # Operator resource settings

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

    ########################################
    # HashiCorp Vault to store operator keys

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

    ####################
    # Indexing settings

    @property
    def start_slot(self) -> StartSlot.Type:
        return self._start_slot

    @property
    def indexer_poll_block_cnt(self) -> int:
        return self._indexer_poll_block_cnt

    @property
    def indexer_check_msec(self) -> int:
        return self._indexer_check_msec

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
    def metrics_log_skip_cnt(self) -> int:
        return self._metrics_log_skip_cnt

    @property
    def genesis_timestamp(self) -> int:
        return self._genesis_timestamp

    @property
    def operator_account_set(self) -> Set[str]:
        return self._op_acct_set

    ######################################
    # Integration Indexer with Tracer API
    @property
    def slot_processing_delay(self) -> int:
        """Slot processing delay relative to the last confirmed slot on Tracer API node"""
        return self._slot_processing_delay

    @property
    def ch_dsn_list(self) -> List[str]:
        """List of DSN addresses of clickhouse servers used by Tracer API node"""
        return self._ch_dsn_list

    ###########################
    # ReIndexing configuration

    @property
    def reindex_start_slot(self) -> StartSlot.Type:
        return self._reindex_start_slot

    @property
    def reindex_thread_cnt(self) -> int:
        return self._reindex_thread_cnt

    @property
    def reindex_range_len(self) -> int:
        return self._reindex_range_len

    @property
    def reindex_max_range_cnt(self) -> int:
        return self._reindex_max_range_cnt

    #######################################
    # gas-less transactions configuration

    @property
    def gas_tank_parallel_request_cnt(self) -> int:
        return self._gas_tank_parallel_request_cnt

    @property
    def gas_tank_poll_tx_cnt(self) -> int:
        return self._gas_tank_poll_tx_cnt

    @property
    def gas_less_tx_max_nonce(self) -> int:
        return self._gas_less_tx_max_nonce

    @property
    def gas_less_tx_max_gas(self) -> int:
        return self._gas_less_tx_max_gas

    ##############################
    # testing settings

    @property
    def fuzz_fail_pct(self) -> int:
        return self._fuzz_fail_pct

    def as_dict(self) -> dict:
        config_dict = {
            'EVM_LOADER_ID': EVM_PROGRAM_ID_STR,

            'SOLANA_TIMEOUT': self.solana_timeout,
            'HIDE_SOLANA_URL': self.hide_solana_url,

            'ENABLE_PRIVATE_API': self.enable_private_api,
            'ENABLE_SEND_TX_API': self.enable_send_tx_api,
            'USE_EARLIEST_BLOCK_IF_0_PASSED': self.use_earliest_block_if_0_passed,
            'NEON_CLI_TIMEOUT': self.neon_cli_timeout,
            'MAX_EVM_STEP_COUNT_TO_EMULATE': self.max_evm_step_cnt_emulate,
            'NEON_CLI_DEBUG_LOG': self.neon_cli_debug_log,
            'GATHER_STATISTICS': self.gather_statistics,

            # Mempool settings
            'MEMPOOL_CAPACITY': self.mempool_capacity,
            'MEMPOOL_EXECUTOR_LIMIT_CNT': self.mempool_executor_limit_cnt,
            'MEMPOOL_CACHE_LIFE_SEC': self.mempool_cache_life_sec,

            # Transaction execution settings
            'RETRY_ON_FAIL': self.retry_on_fail,
            'CONFIRM_TIMEOUT_SEC': self.confirm_timeout_sec,
            'COMMIT_LEVEL': self.commit_type,
            'MAX_TX_ACCOUNT_COUNT': self.max_tx_account_cnt,

            # Gas price settings
            # 'PP_SOLANA_URL': self.pyth_solana_url,
            'PYTH_MAPPING_ACCOUNT': str(self.pyth_mapping_account),
            'UPDATE_PYTH_MAPPING_PERIOD_SEC': self.update_pyth_mapping_period_sec,
            'OPERATOR_FEE': self.operator_fee,
            'GAS_PRICE_SLIPPAGE': self.gas_price_slippage,

            'MINIMAL_GAS_PRICE': self.min_gas_price,
            'MINIMAL_WO_CHAINID_GAS_PRICE': self.min_wo_chainid_gas_price,
            'ALLOW_UNDERPRICED_TX_WITHOUT_CHAINID': self.allow_underpriced_tx_wo_chainid,

            'CONST_GAS_PRICE': self.const_gas_price,

            # Operator resources
            'HOLDER_SIZE': self.holder_size,
            'MIN_OPERATOR_BALANCE_TO_WARN': self.min_operator_balance_to_warn,
            'MIN_OPERATOR_BALANCE_TO_ERR': self.min_operator_balance_to_err,
            'PERM_ACCOUNT_ID': self.perm_account_id,
            'PERM_ACCOUNT_LIMIT': self.perm_account_limit,
            'RECHECK_USED_RESOURCE_SEC': self.recheck_used_resource_sec,
            'RECHECK_RESOURCE_AFTER_USES_CNT': self.recheck_resource_after_uses_cnt,

            # Indexing settings
            self.start_slot_name: self.start_slot,
            'INDEXER_POLL_BLOCK_COUNT': self.indexer_poll_block_cnt,
            'INDEXER_CHECK_MSEC': self.indexer_check_msec,
            'STUCK_OBJECT_BLOCKOUT': self.stuck_object_blockout,
            'STUCK_OBJECT_VALIDATE_BLOCKOUT': self.stuck_object_validate_blockout,
            'ALT_FREEING_DEPTH': self.alt_freeing_depth,
            'METRICS_LOG_SKIP_COUNT': self.metrics_log_skip_cnt,
            'OPERATOR_ACCOUNT_LIST': ';'.join(list(self.operator_account_set)),
            'GENESIS_BLOCK_TIMESTAMP': self.genesis_timestamp,

            # HashiCorp Vault settings
            # 'HVAC_URL': self.hvac_url,
            # 'HVAC_TOKEN': self.hvac_token,
            # 'HVAC_PATH': self.hvac_path,
            # 'HVAC_MOUNT': self.hvac_mount,ga

            # Integration Indexer with Tracer API
            'SLOT_PROCESSING_DELAY': self.slot_processing_delay,
            # 'CLICKHOUSE_DSN_LIST': ';'.join(self.ch_dsn_list),

            # Reindexing settings
            self.reindex_start_slot_name: self.reindex_start_slot,
            self.reindex_thread_cnt_name: self.reindex_thread_cnt,
            'REINDEX_BLOCK_COUNT_IN_RANGE': self.reindex_range_len,
            'REINDEX_MAX_RANGE_COUNT': self.reindex_max_range_cnt,

            # Gas-less transaction configuration
            'GAS_TANK_PARALLEL_REQUEST_COUNT': self.gas_tank_parallel_request_cnt,
            'GAS_TANK_POLL_TX_COUNT': self.gas_tank_poll_tx_cnt,
            'GAS_LESS_MAX_TX_NONCE': self.gas_less_tx_max_nonce,
            'GAS_LESS_MAX_GAS': self.gas_less_tx_max_gas,

            # Testing settings
            'FUZZ_FAIL_PCT': self.fuzz_fail_pct,
        }
        if not self.hide_solana_url:
            config_dict.update({
                'SOLANA_URL': self.solana_url,
                'SOLANA_WS_URL': self.solana_ws_url,
            })
        config_dict.update(super().as_dict())
        return config_dict
