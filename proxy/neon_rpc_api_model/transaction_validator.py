from __future__ import annotations

from typing import Dict, Any

from ..common_neon.config import Config
from ..common_neon.data import NeonTxExecCfg, NeonEmulatedResult
from ..common_neon.elf_params import ElfParams
from ..common_neon.emulator_interactor import call_tx_emulated, check_emulated_exit_status
from ..common_neon.errors import EthereumError, NonceTooLowError
from ..common_neon.utils.eth_proto import NeonTx
from ..common_neon.solana_interactor import SolInteractor

from .estimate import GasEstimate


class NeonTxValidator:
    _max_u64 = 2 ** 64 - 1
    _max_u256 = 2 ** 256 - 1

    def __init__(self, config: Config, solana: SolInteractor, tx: NeonTx, gas_less_permit: bool, min_gas_price: int):
        self._config = config
        self._solana = solana
        self._tx = tx

        self._neon_account_info = solana.get_neon_account_info(self._tx.sender)
        self._state_tx_cnt = solana.get_state_tx_cnt(self._neon_account_info)

        self._has_gas_less_permit = gas_less_permit
        self._min_gas_price = min_gas_price
        self._estimated_gas = 0

        self._tx_gas_limit = self._tx.gasLimit
        self._init_tx_gas_limit()

    def _init_tx_gas_limit(self) -> None:
        if self._tx.has_chain_id() or (not self._config.allow_underpriced_tx_wo_chainid):
            return

        if len(self._tx.callData) == 0:
            return

        no_chainid_gas_limit_multiplier = ElfParams().neon_gas_limit_multiplier_no_chainid
        tx_gas_limit = self._tx_gas_limit * no_chainid_gas_limit_multiplier
        if self._max_u64 > tx_gas_limit:
            self._tx_gas_limit = tx_gas_limit

    def is_underpriced_tx_wo_chainid(self) -> bool:
        if self._tx.has_chain_id():
            return False
        return (self._tx.gasPrice < self._min_gas_price) or (self._tx.gasLimit < self._estimated_gas)

    def validate(self) -> NeonTxExecCfg:
        self._prevalidate_tx()
        if self._config.accept_reverted_tx_into_mempool:
            emulated_result: NeonEmulatedResult = dict()
        else:
            emulated_result: NeonEmulatedResult = call_tx_emulated(self._config, self._tx)
            self._prevalidate_emulator(emulated_result)

        neon_tx_exec_cfg = NeonTxExecCfg().set_emulated_result(emulated_result).set_state_tx_cnt(self._state_tx_cnt)
        return neon_tx_exec_cfg

    def _prevalidate_tx(self):
        self._prevalidate_sender_eoa()
        self._prevalidate_tx_gas()
        self._prevalidate_tx_chain_id()
        self._prevalidate_tx_size()
        self._prevalidate_sender_balance()
        self._prevalidate_underpriced_tx_wo_chainid()
        self._validate_nonce()

    def _prevalidate_emulator(self, emulator_json: Dict[str, Any]):
        check_emulated_exit_status(emulator_json)
        self._prevalidate_gas_usage(emulator_json)

        self._prevalidate_account_sizes(emulator_json)
        self._prevalidate_account_cnt(emulator_json)

    def _prevalidate_tx_gas(self):
        if self._tx_gas_limit > self._max_u64:
            raise EthereumError(message='gas uint64 overflow')
        if (self._tx_gas_limit * self._tx.gasPrice) > (self._max_u256 - 1):
            raise EthereumError(message='max fee per gas higher than 2^256-1')

        # Operator can set minimum gas price to accept txs into mempool
        if self._tx.gasPrice >= self._config.min_gas_price:
            return

        # Gas-less transaction
        if (self._tx.gasPrice == 0) and self._has_gas_less_permit:
            return

        if self._config.allow_underpriced_tx_wo_chainid:
            if (not self._tx.has_chain_id()) and (self._tx.gasPrice >= self._config.min_wo_chainid_gas_price):
                return

        raise EthereumError(f'transaction underpriced: have {self._tx.gasPrice} want {self._config.min_gas_price}')

    def _prevalidate_tx_chain_id(self):
        if self._tx.chain_id() not in (None, ElfParams().chain_id):
            raise EthereumError(message='wrong chain id')

    def _prevalidate_tx_size(self):
        if len(self._tx.callData) > (128 * 1024 - 1024):
            raise EthereumError(message='transaction size is too big')

    def _prevalidate_sender_eoa(self):
        if not self._neon_account_info:
            return

        if self._neon_account_info.code_size > 0:
            raise EthereumError(message='sender not an eoa')

    def _prevalidate_sender_balance(self):
        if self._neon_account_info:
            user_balance = self._neon_account_info.balance
        else:
            user_balance = 0

        required_balance = self._tx.gasPrice * self._tx_gas_limit + self._tx.value

        if required_balance <= user_balance:
            return

        if len(self._tx.callData) == 0:
            message = 'insufficient funds for transfer'
        else:
            message = 'insufficient funds for gas * price + value'

        raise EthereumError(f'{message}: address {self._tx.hex_sender} have {user_balance} want {required_balance}')

    def _prevalidate_gas_usage(self, emulator_json: dict):
        request = {
            'from': self._tx.hex_sender,
            'to': self._tx.hex_to_address,
            'data': self._tx.hex_call_data,
            'value': hex(self._tx.value)
        }

        calculator = GasEstimate(self._config, self._solana, request)
        calculator.emulator_json = emulator_json
        self._estimated_gas = calculator.estimate()

        if self._estimated_gas <= self._tx_gas_limit:
            return

        message = 'gas limit reached'
        raise EthereumError(f'{message}: have {self._tx_gas_limit} want {self._estimated_gas}')

    def _prevalidate_underpriced_tx_wo_chainid(self):
        if not self.is_underpriced_tx_wo_chainid():
            return
        if self._config.allow_underpriced_tx_wo_chainid:
            return

        raise EthereumError("proxy configuration doesn't allow underpriced transaction without chain-id")

    @staticmethod
    def _prevalidate_account_sizes(emulator_json: Dict[str, Any]):
        for account_desc in emulator_json['accounts']:
            if ('size' not in account_desc) or ('address' not in account_desc):
                continue
            if (not account_desc['size']) or (not account_desc['address']):
                continue
            if account_desc['size'] > ((9 * 1024 + 512) * 1024):
                raise EthereumError(f"contract {account_desc['address']} requests a size increase to more than 9.5Mb")

    def _prevalidate_account_cnt(self, emulator_json: Dict[str, Any]):
        account_cnt = (
            len(emulator_json.get('accounts', list())) +
            len(emulator_json.get('solana_accounts', list()))
        )

        if account_cnt > self._config.max_tx_account_cnt:
            raise EthereumError(f'transaction requires too lot of accounts {account_cnt}')

    def _validate_nonce(self) -> None:
        tx_nonce = int(self._tx.nonce)
        tx_sender = self._tx.hex_sender
        state_tx_cnt = self._state_tx_cnt

        if self._max_u64 in (self._state_tx_cnt, tx_nonce):
            raise EthereumError(
                code=NonceTooLowError.eth_error_code,
                message=f'nonce has max value: address {tx_sender}, tx: {tx_nonce} state: {state_tx_cnt}'
            )

        NonceTooLowError.raise_if_error(tx_sender, tx_nonce, state_tx_cnt)
