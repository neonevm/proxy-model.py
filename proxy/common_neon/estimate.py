import json
import rlp
from logged_groups import logged_group

from proxy.common_neon.emulator_interactor import call_emulated
from ..common_neon.elf_params import ElfParams

from .environment_data import EXTRA_GAS
from .eth_proto import Trx as EthTrx
from .solana_interactor import SolanaInteractor
from .solana_alt_builder import AddressLookupTableTxBuilder


@logged_group("neon.Proxy")
class GasEstimate:
    def __init__(self, request: dict, solana: SolanaInteractor):
        self._sender = request.get('from') or '0x0000000000000000000000000000000000000000'
        if self._sender:
            self._sender = self._sender[2:]

        self._contract = request.get('to') or ''
        if self._contract:
            self._contract = self._contract[2:]

        self._data = request.get('data') or ''
        if self._data:
            self._data = self._data[2:]

        self._value = request.get('value') or '0x00'

        self._solana = solana

        self.emulator_json = {}

    def execute(self):
        self.emulator_json = call_emulated(self._contract or "deploy", self._sender, self._data, self._value)
        self.debug(f'emulator returns: {json.dumps(self.emulator_json, sort_keys=True)}')

    def _trx_size_cost(self) -> int:
        u256_max = int.from_bytes(bytes([0xFF] * 32), "big")

        trx = EthTrx(
            nonce=u256_max,
            gasPrice=u256_max,
            gasLimit=u256_max,
            toAddress=bytes.fromhex(self._contract),
            value=int(self._value, 16),
            callData=bytes.fromhex(self._data),
            v=ElfParams().chain_id * 2 + 35,
            r=0x1820182018201820182018201820182018201820182018201820182018201820,
            s=0x1820182018201820182018201820182018201820182018201820182018201820
        )
        msg = rlp.encode(trx)
        return ((len(msg) // ElfParams().holder_msg_size) + 1) * 5000

    @staticmethod
    def _iterative_overhead_cost() -> int:
        last_iteration_cost = 5000
        cancel_cost = 5000

        return last_iteration_cost + cancel_cost

    def alt_cost(self) -> int:
        # ALT used by TransactionStepFromAccount, TransactionStepFromAccountNoChainId which have 6 fixed accounts
        acc_cnt = len(self.emulator_json.get("accounts", [])) + len(self.emulator_json.get("solana_accounts", [])) + 6
        if acc_cnt > AddressLookupTableTxBuilder.TX_ACCOUNT_CNT:
            return 5000 * 12  # ALT ix: create + ceil(256/30) extend + deactivate + close
        else:
            return 0

    def estimate(self):
        execution_cost = self.emulator_json.get('used_gas', 0)
        trx_size_cost = self._trx_size_cost()
        overhead = self._iterative_overhead_cost()
        alt_cost = self.alt_cost()

        gas = max(21000, execution_cost + trx_size_cost + overhead + alt_cost + EXTRA_GAS)

        self.debug(f'execution_cost: {execution_cost}, ' +
                   f'trx_size_cost: {trx_size_cost}, ' +
                   f'iterative_overhead: {overhead}, ' +
                   f'alt_cost: {alt_cost}, ' +
                   f'extra_gas: {EXTRA_GAS}, ' +
                   f'estimated gas: {gas}')

        return gas
