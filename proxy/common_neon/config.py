import os
from typing import Optional
from decimal import Decimal

from ..common_neon.solana_transaction import SolPubKey
from ..common_neon.environment_data import EVM_LOADER_ID, SOLANA_URL, RETRY_ON_FAIL


class Config:
    def __init__(self):
        self._solana_url = SOLANA_URL
        self._pp_solana_url = os.environ.get("PP_SOLANA_URL", SOLANA_URL)
        self._evm_loader_id = SolPubKey(EVM_LOADER_ID)
        self._evm_step_cnt_inc_pct = self._env_decimal("EVM_STEP_COUNT_INC_PCT", "0.5")
        self._mempool_capacity = self._env_int("MEMPOOL_CAPACITY", 10, 4096)
        self._holder_size = self._env_int("HOLDER_SIZE", 1024, 131072)  # 128*1024
        self._min_op_balance_to_warn = self._env_int("MIN_OPERATOR_BALANCE_TO_WARN", 9000000000, 9000000000)
        self._min_op_balance_to_err = self._env_int("MIN_OPERATOR_BALANCE_TO_ERR", 1000000000, 1000000000)
        self._perm_account_id = self._env_int("PERM_ACCOUNT_ID", 1, 1)
        self._perm_account_limit = self._env_int("PERM_ACCOUNT_LIMIT", 1, 2)
        self._recheck_used_resource_sec = self._env_int('RECHECK_USED_RESOURCE_SEC', 10, 60)
        self._recheck_resource_after_uses_cnt = self._env_int("RECHECK_RESOURCE_AFTER_USES_CNT", 10, 60)
        self._retry_on_fail = RETRY_ON_FAIL
        self._enable_private_api = self._env_bool("ENABLE_PRIVATE_API", False)
        self._use_earliest_block_if_0_passed = self._env_bool("USE_EARLIEST_BLOCK_IF_0_PASSED", False)
        self._account_permission_update_int = self._env_int("ACCOUNT_PERMISSION_UPDATE_INT", 10, 60 * 5)
        self._allow_underpriced_tx_wo_chainid = self._env_bool("ALLOW_UNDERPRICED_TX_WITHOUT_CHAINID", False)
        self._contract_extra_space = self._env_int("CONTRACT_EXTRA_SPACE", 0, 2048)
        self._extra_gas_pct = self._env_decimal("EXTRA_GAS_PCT", "0.0")
        self._operator_fee = self._env_decimal("OPERATOR_FEE", "0.1")
        self._gas_price_suggested_pct = self._env_decimal("GAS_PRICE_SUGGEST_PCT", "0.01")
        self._min_gas_price = self._env_int("MINIMAL_GAS_PRICE", 0, 0) * (10 ** 9)
        self._neon_price_usd = Decimal('0.25')
        self._neon_decimals = self._env_int('NEON_DECIMALS', 1, 9)
        self._finalized_commitment = os.environ.get('FINALIZED_COMMITMENT', 'finalized')
        self._confirmed_commitment = os.environ.get('CONFIRMED_COMMITMENT', 'confirmed')
        self._start_slot = os.environ.get('START_SLOT', '0')
        self._indexer_parallel_request_cnt = self._env_int("INDEXER_PARALLEL_REQUEST_COUNT", 1, 10)
        self._indexer_poll_cnt = self._env_int("INDEXER_POLL_COUNT", 1, 1000)
        self._max_account_cnt = self._env_int("MAX_ACCOUNT_COUNT", 20, 60)
        self._skip_preflight = self._env_bool("SKIP_PREFLIGHT", False)
        self._fuzzing_blockhash = self._env_bool("FUZZING_BLOCKHASH", False)
        self._confirm_timeout_sec = self._env_int("CONFIRM_TIMEOUT_SEC", 10, 10)
        self._confirm_check_msec = self._env_int("CONFIRM_CHECK_MSEC", 10, 100)

        pyth_mapping_account = os.environ.get("PYTH_MAPPING_ACCOUNT", None)
        self._pyth_mapping_account = SolPubKey(pyth_mapping_account) if pyth_mapping_account is not None else None

        self._validate()

    def _validate(self) -> None:
        assert (self._operator_fee > 0) and (self._operator_fee < 1)
        assert (self._gas_price_suggested_pct >= 0) and (self._gas_price_suggested_pct < 1)
        assert (self._extra_gas_pct >= 0) and (self._extra_gas_pct < 1)

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
    def solana_url(self) -> str:
        return self._solana_url

    @property
    def evm_step_cnt_inc_pct(self) -> Decimal:
        return self._evm_step_cnt_inc_pct

    @property
    def mempool_capacity(self) -> int:
        return self._mempool_capacity

    @property
    def pyth_mapping_account(self) -> Optional[SolPubKey]:
        return self._pyth_mapping_account

    @property
    def pyth_solana_url(self) -> str:
        return self._pp_solana_url

    @property
    def evm_loader_id(self) -> SolPubKey:
        return self._evm_loader_id

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
    def use_earliest_block_if_0_passed(self) -> bool:
        return self._use_earliest_block_if_0_passed

    @property
    def account_permission_update_int(self) -> int:
        return self._account_permission_update_int

    @property
    def allow_underpriced_tx_wo_chainid(self) -> bool:
        return self._allow_underpriced_tx_wo_chainid

    @property
    def extra_gas_pct(self) -> Decimal:
        return self._extra_gas_pct

    @property
    def contract_extra_space(self) -> int:
        return self._contract_extra_space

    @property
    def operator_fee(self) -> Decimal:
        return self._operator_fee

    @property
    def gas_price_suggested_pct(self) -> Decimal:
        return self._gas_price_suggested_pct

    @property
    def min_gas_price(self) -> Optional[int]:
        if self._min_gas_price > 0:
            return self._min_gas_price
        return None

    @property
    def neon_price_usd(self) -> Decimal:
        return self._neon_price_usd

    @property
    def neon_decimals(self) -> int:
        return self._neon_decimals

    @property
    def finalized_commitment(self) -> str:
        return self._finalized_commitment

    @property
    def confirmed_commitment(self) -> str:
        return self._confirmed_commitment

    @property
    def start_slot(self) -> str:
        return self._start_slot

    @property
    def indexer_parallel_request_cnt(self) -> int:
        return self._indexer_parallel_request_cnt

    @property
    def indexer_poll_cnt(self) -> int:
        return self._indexer_poll_cnt

    @property
    def max_account_cnt(self) -> int:
        return self._max_account_cnt

    @property
    def skip_preflight(self) -> bool:
        return self._skip_preflight

    @property
    def fuzzing_blockhash(self) -> bool:
        return self._fuzzing_blockhash

    @property
    def confirm_timeout_sec(self) -> int:
        return self._confirm_timeout_sec

    @property
    def confirm_check_msec(self) -> int:
        return self._confirm_check_msec

    def __str__(self):
        return '\n        '.join([
            '',
            f"SOLANA_URL: {self.solana_url},",
            f"EVM_LOADER_ID: {self.evm_loader_id},",
            f"PP_SOLANA_URL: {self.pyth_solana_url}",
            f"PYTH_MAPPING_ACCOUNT: {self.pyth_mapping_account}",
            f"EVM_STEP_COUNT_INC_PCT: {self._evm_step_cnt_inc_pct},",
            f"MP_CAPACITY: {self.mempool_capacity}",
            f"HOLDER_SIZE: {self.holder_size}",
            f"MIN_OPERATOR_BALANCE_TO_WARN: {self.min_operator_balance_to_warn}",
            f"MIN_OPERATOR_BALANCE_TO_ERR: {self.min_operator_balance_to_err}",
            f"PERM_ACCOUNT_ID: {self.perm_account_id}",
            f"PERM_ACCOUNT_LIMIT: {self.perm_account_limit}",
            f"RECHECK_USED_RESOURCE_SEC: {self.recheck_used_resource_sec}",
            f"RECHECK_RESOURCE_AFTER_USES_CNT: {self.recheck_resource_after_uses_cnt}",
            f"RETRY_ON_FAIL: {self.retry_on_fail}",
            f"ENABLE_PRIVATE_API: {self.enable_private_api}",
            f"USE_EARLIEST_BLOCK_IF_0_PASSED: {self.use_earliest_block_if_0_passed}",
            f"ACCOUNT_PERMISSION_UPDATE_INT: {self.account_permission_update_int}",
            f"ALLOW_UNDERPRICED_TX_WITHOUT_CHAINID: {self.allow_underpriced_tx_wo_chainid}",
            f"CONTRACT_EXTRA_SPACE: {self.contract_extra_space}",
            f"EXTRA_GAS_PCT: {self.extra_gas_pct}",
            f"OPERATOR_FEE: {self.operator_fee}",
            f"GAS_PRICE_SUGGEST_PCT: {self.gas_price_suggested_pct}",
            f"MINIMAL_GAS_PRICE: {self.min_gas_price}",
            f"NEON_PRICE_USD: {self.neon_price_usd}",
            f"NEON_DECIMALS: {self.neon_decimals}",
            f"FINALIZED_COMMITMENT: {self.finalized_commitment}",
            f"CONFIRMED_COMMITMENT: {self.confirmed_commitment}",
            f"START_SLOT: {self.start_slot}",
            f"INDEXER_PARALLEL_REQUEST_COUNT: {self.indexer_parallel_request_cnt}",
            f"INDEXER_POLL_COUNT: {self.indexer_poll_cnt}",
            f"MAX_ACCOUNT_COUNT: {self.max_account_cnt}",
            f"SKIP_PREFLIGHT: {self.skip_preflight}",
            f"FUZZING_BLOCKHASH: {self.fuzzing_blockhash}",
            f"CONFIRM_TIMEOUT_SEC: {self.confirm_timeout_sec}",
            f"CONFIRM_CHECK_MSEC: {self.confirm_check_msec}",
            ""
        ])
