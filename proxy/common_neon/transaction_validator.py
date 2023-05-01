from __future__ import annotations

from typing import Dict, Any, Optional

from ..common_neon.config import Config
from ..common_neon.data import NeonTxExecCfg, NeonEmulatedResult
from ..common_neon.elf_params import ElfParams
from ..common_neon.emulator_interactor import call_tx_emulated, check_emulated_exit_status
from ..common_neon.errors import EthereumError, NonceTooLowError
from ..common_neon.estimate import GasEstimate
from ..common_neon.eth_proto import NeonTx
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx_error_parser import SolTxErrorParser


class NeonTxValidator:
    max_u64 = 2 ** 64 - 1
    max_u256 = 2 ** 256 - 1

    def __init__(self, config: Config, solana: SolInteractor, tx: NeonTx, gas_less_permit: bool, min_gas_price: int):
        self._solana = solana
        self._config = config
        self._tx = tx

        self._neon_account_info = self._solana.get_neon_account_info(self._tx.sender)
        self._state_tx_cnt = self._neon_account_info.tx_count if self._neon_account_info is not None else 0

        self._has_gas_less_permit = gas_less_permit
        self._min_gas_price = min_gas_price
        self._estimated_gas = 0

        self._tx_gas_limit = self._tx.gasLimit

        if self._tx.has_chain_id() or (not self._config.allow_underpriced_tx_wo_chainid):
            return

        if len(self._tx.callData) == 0:
            return

        no_chainid_gas_limit_multiplier = ElfParams().neon_gas_limit_multiplier_no_chainid
        tx_gas_limit = self._tx_gas_limit * no_chainid_gas_limit_multiplier
        if self.max_u64 > tx_gas_limit:
            self._tx_gas_limit = tx_gas_limit

    def is_underpriced_tx_wo_chainid(self) -> bool:
        if self._tx.has_chain_id():
            return False
        return (self._tx.gasPrice < self._min_gas_price) or (self._tx.gasLimit < self._estimated_gas)

    def precheck(self) -> NeonTxExecCfg:
        try:
            self._prevalidate_tx()
            emulated_result: NeonEmulatedResult = call_tx_emulated(self._config, self._tx)
            self.prevalidate_emulator(emulated_result)

            neon_tx_exec_cfg = NeonTxExecCfg().set_emulated_result(emulated_result).set_state_tx_cnt(self._state_tx_cnt)
            return neon_tx_exec_cfg
        except BaseException as exc:
            self.extract_ethereum_error(exc)
            raise

    def _prevalidate_tx(self):
        self._prevalidate_tx_nonce()
        self._prevalidate_sender_eoa()
        self._prevalidate_tx_gas()
        self._prevalidate_tx_chain_id()
        self._prevalidate_tx_size()
        self._prevalidate_sender_balance()
        self._prevalidate_underpriced_tx_wo_chainid()

    def prevalidate_emulator(self, emulator_json: Dict[str, Any]):
        if not self._config.accept_reverted_tx_into_mempool:
            check_emulated_exit_status(emulator_json)
            self._prevalidate_gas_usage(emulator_json)

        self._prevalidate_account_sizes(emulator_json)
        self._prevalidate_account_cnt(emulator_json)

    def extract_ethereum_error(self, e: BaseException):
        receipt_parser = SolTxErrorParser(e)
        state_tx_cnt, tx_nonce = receipt_parser.get_nonce_error()
        self._raise_if_nonce_error(state_tx_cnt, tx_nonce)

    def _prevalidate_tx_gas(self):
        if self._tx_gas_limit > self.max_u64:
            raise EthereumError(message='gas uint64 overflow')
        if (self._tx_gas_limit * self._tx.gasPrice) > (self.max_u256 - 1):
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

    def _prevalidate_tx_nonce(self):
        tx_nonce = int(self._tx.nonce)
        if self.max_u64 in (self._state_tx_cnt, tx_nonce):
            sender = self._tx.hex_sender
            raise EthereumError(
                code=-32002,
                message=f'nonce has max value: address {sender}, tx: {tx_nonce} state: {self._state_tx_cnt}'
            )

        self._raise_if_nonce_error(self._state_tx_cnt, tx_nonce)

    def _prevalidate_sender_eoa(self):
        if not self._neon_account_info:
            return

        if self._neon_account_info.code_size > 0:
            raise EthereumError("sender not an eoa")

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

        raise EthereumError(f"{message}: address {self._tx.hex_sender} have {user_balance} want {required_balance}")

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
        raise EthereumError(f"{message}: have {self._tx_gas_limit} want {self._estimated_gas}")

    def _prevalidate_underpriced_tx_wo_chainid(self):
        if not self.is_underpriced_tx_wo_chainid():
            return
        if self._config.allow_underpriced_tx_wo_chainid:
            return

        raise EthereumError(f"proxy configuration doesn't allow underpriced transaction without chain-id")

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
            len(emulator_json.get("accounts", [])) +
            len(emulator_json.get("token_accounts", [])) +
            len(emulator_json.get("solana_accounts", []))
        )
        if account_cnt > self._config.max_tx_account_cnt:
            raise EthereumError(f"transaction requires too lot of accounts {account_cnt}")

    def _raise_if_nonce_error(self, state_tx_cnt: Optional[int], tx_nonce: Optional[int]):
        if (state_tx_cnt is None) and (tx_nonce is None):
            return

        NonceTooLowError.raise_if_error(self._tx.hex_sender, tx_nonce, state_tx_cnt)

