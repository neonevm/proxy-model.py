from __future__ import annotations
from logged_groups import logged_group

from ..common_neon.eth_proto import NeonTx
from ..common_neon.address import EthereumAddress
from ..common_neon.errors import EthereumError
from ..common_neon.account_whitelist import AccountWhitelist
from ..common_neon.solana_tx_error_parser import SolTxErrorParser
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.estimate import GasEstimate
from ..common_neon.emulator_interactor import call_trx_emulated

from ..common_neon.elf_params import ElfParams
from ..common_neon.config import Config

from ..common_neon.data import NeonTxExecCfg, NeonEmulatedResult


@logged_group("neon.Proxy")
class NeonTxValidator:
    MAX_U64 = pow(2, 64) - 1
    MAX_U256 = pow(2, 256) - 1

    def __init__(self, config: Config, solana: SolInteractor, tx: NeonTx, min_gas_price: int):
        self._solana = solana
        self._config = config
        self._tx = tx

        self._sender = '0x' + tx.sender()
        self._neon_account_info = self._solana.get_neon_account_info(EthereumAddress(self._sender))
        self._state_tx_cnt = self._neon_account_info.tx_count if self._neon_account_info is not None else 0

        self._deployed_contract = tx.contract()
        if self._deployed_contract:
            self._deployed_contract = '0x' + self._deployed_contract

        self._to_address = tx.toAddress.hex()
        if self._to_address:
            self._to_address = '0x' + self._to_address

        self._tx_hash = '0x' + self._tx.hash_signed().hex()
        self._min_gas_price = min_gas_price
        self._estimated_gas = 0

        self._tx_gas_limit = self._tx.gasLimit

        if self._tx.hasChainId() or (not self._config.allow_underpriced_tx_wo_chainid):
            return

        if len(self._tx.callData) == 0:
            return
        no_chainid_gas_limit_multiplier = ElfParams().neon_gas_limit_multiplier_no_chainid
        tx_gas_limit = self._tx_gas_limit * no_chainid_gas_limit_multiplier
        if self.MAX_U64 > tx_gas_limit:
            self._tx_gas_limit = tx_gas_limit

    def is_underpriced_tx_without_chainid(self) -> bool:
        if self._tx.hasChainId():
            return False
        return (self._tx.gasPrice < self._min_gas_price) or (self._tx.gasLimit < self._estimated_gas)

    def precheck(self) -> NeonTxExecCfg:
        try:
            self._prevalidate_tx()
            emulated_result: NeonEmulatedResult = call_trx_emulated(self._tx)
            self.prevalidate_emulator(emulated_result)

            neon_tx_exec_cfg = NeonTxExecCfg().set_emulated_result(emulated_result).set_state_tx_cnt(self._state_tx_cnt)
            return neon_tx_exec_cfg
        except BaseException as exc:
            self.extract_ethereum_error(exc)
            raise

    def _prevalidate_tx(self):
        self._prevalidate_whitelist()
        self._prevalidate_tx_nonce()
        self._prevalidate_sender_eoa()
        self._prevalidate_tx_gas()
        self._prevalidate_tx_chain_id()
        self._prevalidate_tx_size()
        self._prevalidate_sender_balance()
        self._prevalidate_underpriced_tx_without_chainid()

    def prevalidate_emulator(self, emulator_json: dict):
        self._prevalidate_gas_usage(emulator_json)
        self._prevalidate_account_sizes(emulator_json)
        self._prevalidate_account_cnt(emulator_json)

    def extract_ethereum_error(self, e: BaseException):
        receipt_parser = SolTxErrorParser(e)
        state_tx_cnt, tx_nonce = receipt_parser.get_nonce_error()
        if state_tx_cnt is not None:
            self.raise_nonce_error(state_tx_cnt, tx_nonce)

    def _prevalidate_whitelist(self):
        w = AccountWhitelist(self._config, self._solana)
        if not w.has_client_permission(self._sender[2:]):
            self.warning(f'Sender account {self._sender} is not allowed to execute transactions')
            raise EthereumError(message=f'Sender account {self._sender} is not allowed to execute transactions')

        if (self._deployed_contract is not None) and (not w.has_contract_permission(self._deployed_contract[2:])):
            self.warning(f'Contract account {self._deployed_contract} is not allowed for deployment')
            raise EthereumError(message=f'Contract account {self._deployed_contract} is not allowed for deployment')

    def _prevalidate_tx_gas(self):
        if self._tx_gas_limit > self.MAX_U64:
            raise EthereumError(message='gas uint64 overflow')
        if (self._tx_gas_limit * self._tx.gasPrice) > (self.MAX_U256 - 1):
            raise EthereumError(message='max fee per gas higher than 2^256-1')

        if self._tx.gasPrice >= self._min_gas_price:
            return

        if self._config.allow_underpriced_tx_wo_chainid:
            if (not self._tx.hasChainId()) and (self._tx.gasPrice >= 10**10):
                return

        raise EthereumError(message=f"transaction underpriced: have {self._tx.gasPrice} want {self._min_gas_price}")

    def _prevalidate_tx_chain_id(self):
        if self._tx.chainId() not in (None, ElfParams().chain_id):
            raise EthereumError(message='wrong chain id')

    def _prevalidate_tx_size(self):
        if len(self._tx.callData) > (128 * 1024 - 1024):
            raise EthereumError(message='transaction size is too big')

    def _prevalidate_tx_nonce(self):
        tx_nonce = int(self._tx.nonce)
        if self.MAX_U64 in (self._state_tx_cnt, tx_nonce):
            raise EthereumError(
                code=-32002,
                message=f'nonce has max value: address {self._sender}, tx: {tx_nonce} state: {self._state_tx_cnt}'
            )
        if self._state_tx_cnt > tx_nonce:
            self.raise_nonce_error(self._state_tx_cnt, tx_nonce)

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

        raise EthereumError(f"{message}: address {self._sender} have {user_balance} want {required_balance}")

    def _prevalidate_gas_usage(self, emulator_json: dict):
        request = {
            'from': self._sender,
            'to': self._to_address,
            'data': self._tx.callData.hex(),
            'value': hex(self._tx.value)
        }

        calculator = GasEstimate(self._config, self._solana, request)
        calculator.emulator_json = emulator_json
        self._estimated_gas = calculator.estimate()

        if self._estimated_gas <= self._tx_gas_limit:
            return

        message = 'gas limit reached'
        raise EthereumError(f"{message}: have {self._tx_gas_limit} want {self._estimated_gas}")

    def _prevalidate_underpriced_tx_without_chainid(self):
        if not self.is_underpriced_tx_without_chainid():
            return
        if self._config.allow_underpriced_tx_wo_chainid:
            return

        raise EthereumError(f"proxy configuration doesn't allow underpriced transaction without chain-id")

    @staticmethod
    def _prevalidate_account_sizes(emulator_json: dict):
        for account_desc in emulator_json['accounts']:
            if ('size' not in account_desc) or ('address' not in account_desc):
                continue
            if (not account_desc['size']) or (not account_desc['address']):
                continue
            if account_desc['size'] > ((9 * 1024 + 512) * 1024):
                raise EthereumError(
                    f"contract {account_desc['address']} " +
                    f"requests a size increase to more than 9.5Mb"
                )

    def _prevalidate_account_cnt(self, emulator_json: dict):
        account_cnt = len(emulator_json.get("accounts", [])) + \
                      len(emulator_json.get("token_accounts", [])) + \
                      len(emulator_json.get("solana_accounts", []))
        if account_cnt > self._config.max_account_cnt:
            raise EthereumError(f"transaction requires too lot of accounts {account_cnt}")

    def raise_nonce_error(self, state_tx_cnt: int, tx_nonce: int):
        if state_tx_cnt > tx_nonce:
            message = 'nonce too low'
        else:
            message = 'nonce too high'

        raise EthereumError(
            code=-32002,
            message=f'{message}: address {self._sender}, tx: {tx_nonce} state: {state_tx_cnt}'
        )
