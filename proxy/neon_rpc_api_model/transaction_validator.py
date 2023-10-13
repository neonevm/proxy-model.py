from __future__ import annotations

from typing import List

from ..common_neon.config import Config
from ..common_neon.data import NeonTxExecCfg
from ..common_neon.evm_config import EVMConfig
from ..common_neon.errors import EthereumError, NonceTooLowError
from ..common_neon.utils.eth_proto import NeonTx
from ..common_neon.address import NeonAddress

from ..neon_core_api.neon_core_api_client import NeonCoreApiClient
from ..neon_core_api.neon_layouts import NeonAccountInfo, NeonContractInfo


class NeonTxValidator:
    _max_u64 = 2 ** 64 - 1
    _max_u256 = 2 ** 256 - 1

    def __init__(self, cfg: Config, client: NeonCoreApiClient, def_chain_id: int, valid_chain_id_list: List[int]):
        self._config = cfg
        self._core_api_client = client
        self._def_chain_id = def_chain_id
        self._valid_chain_id_list = valid_chain_id_list

    def _get_tx_gas_limit(self, neon_tx: NeonTx) -> int:
        if neon_tx.has_chain_id() or (not self._config.allow_underpriced_tx_wo_chainid):
            return neon_tx.gasLimit

        if len(neon_tx.callData) == 0:
            return neon_tx.gasLimit

        no_chainid_gas_limit_multiplier = EVMConfig().neon_gas_limit_multiplier_no_chainid
        tx_gas_limit = neon_tx.gasLimit * no_chainid_gas_limit_multiplier
        if self._max_u64 > tx_gas_limit:
            return tx_gas_limit
        return neon_tx.gasLimit

    def _is_underpriced_tx_wo_chainid(self, neon_tx: NeonTx, min_gas_price: int) -> bool:
        return (not neon_tx.has_chain_id()) and (neon_tx.gasPrice < min_gas_price)

    def validate(self, neon_tx: NeonTx, gas_limit_permit: bool, min_gas_price: int) -> NeonTxExecCfg:
        chain_id = neon_tx.chain_id or self._def_chain_id

        sender_addr = NeonAddress.from_raw(neon_tx.sender, chain_id)
        neon_account_info = self._core_api_client.get_neon_account_info(sender_addr)
        neon_contract_info = self._core_api_client.get_neon_contract_info(sender_addr)
        state_tx_cnt = self._core_api_client.get_state_tx_cnt(neon_account_info)

        tx_gas_limit = self._get_tx_gas_limit(neon_tx)

        self._prevalidate_sender_eoa(neon_contract_info)
        self._prevalidate_tx_chain_id(chain_id)
        self._prevalidate_tx_size(neon_tx)
        self._prevalidate_tx_gas(neon_tx, tx_gas_limit, gas_limit_permit)
        self._prevalidate_sender_balance(neon_tx, neon_account_info, tx_gas_limit)
        self._prevalidate_underpriced_tx_wo_chainid(neon_tx, min_gas_price)
        self._validate_nonce(neon_tx, state_tx_cnt)
        self._prevalidate_min_tx_gas(tx_gas_limit)

        neon_tx_exec_cfg = NeonTxExecCfg().set_state_tx_cnt(state_tx_cnt)
        return neon_tx_exec_cfg

    def _prevalidate_tx_gas(self, neon_tx: NeonTx, tx_gas_limit: int, has_gas_less_permit: bool):
        if tx_gas_limit > self._max_u64:
            raise EthereumError(message='gas uint64 overflow')
        if (tx_gas_limit * neon_tx.gasPrice) > (self._max_u256 - 1):
            raise EthereumError(message='max fee per gas higher than 2^256-1')

        # Operator can set minimum gas price to accept txs into mempool
        if neon_tx.gasPrice >= self._config.min_gas_price:
            return

        # Gas-less transaction
        if (neon_tx.gasPrice == 0) and has_gas_less_permit:
            return

        if self._config.allow_underpriced_tx_wo_chainid:
            if (not neon_tx.has_chain_id()) and (neon_tx.gasPrice >= self._config.min_wo_chainid_gas_price):
                return

        raise EthereumError(f'transaction underpriced: have {neon_tx.gasPrice} want {self._config.min_gas_price}')

    @staticmethod
    def _prevalidate_min_tx_gas(tx_gas_limit: int):
        if tx_gas_limit < 21_000:
            raise EthereumError(message='gas limit reached')

    def _prevalidate_tx_chain_id(self, chain_id: int):
        if chain_id not in self._valid_chain_id_list:
            raise EthereumError(message='wrong chain id')

    @staticmethod
    def _prevalidate_tx_size(neon_tx: NeonTx):
        if len(neon_tx.callData) > (128 * 1024 - 1024):
            raise EthereumError(message='transaction size is too big')

    @staticmethod
    def _prevalidate_sender_eoa(neon_contract_info: NeonContractInfo):
        if neon_contract_info.chain_id:
            raise EthereumError(message='sender not an eoa')

    def _prevalidate_sender_balance(self, neon_tx: NeonTx, neon_account_info: NeonAccountInfo, tx_gas_limit: int):
        user_balance = neon_account_info.balance

        required_balance = neon_tx.gasPrice * tx_gas_limit + neon_tx.value

        if required_balance <= user_balance:
            return

        if len(neon_tx.callData) == 0:
            message = 'insufficient funds for transfer'
        else:
            message = 'insufficient funds for gas * price + value'

        raise EthereumError(f'{message}: address {neon_tx.hex_sender} have {user_balance} want {required_balance}')

    def _prevalidate_underpriced_tx_wo_chainid(self, neon_tx: NeonTx, min_gas_price: int):
        if not self._is_underpriced_tx_wo_chainid(neon_tx, min_gas_price):
            return
        if self._config.allow_underpriced_tx_wo_chainid:
            return

        raise EthereumError("proxy configuration doesn't allow underpriced transaction without chain-id")

    def _validate_nonce(self, neon_tx: NeonTx, state_tx_cnt: int) -> None:
        tx_nonce = int(neon_tx.nonce)
        tx_sender = neon_tx.hex_sender
        state_tx_cnt = state_tx_cnt

        if self._max_u64 in (state_tx_cnt, tx_nonce):
            raise EthereumError(
                code=NonceTooLowError.eth_error_code,
                message=f'nonce has max value: address {tx_sender}, tx: {tx_nonce} state: {state_tx_cnt}'
            )

        NonceTooLowError.raise_if_error(tx_sender, tx_nonce, state_tx_cnt)
