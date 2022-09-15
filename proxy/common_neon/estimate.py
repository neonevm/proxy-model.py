import json
import rlp
import math
from logged_groups import logged_group

from proxy.common_neon.emulator_interactor import call_emulated
from ..common_neon.elf_params import ElfParams

from .config import Config
from .eth_proto import NeonTx
from .solana_interactor import SolanaInteractor
from .layouts import ACCOUNT_INFO_LAYOUT


@logged_group("neon.Proxy")
class GasEstimate:
    def __init__(self, request: dict, solana: SolanaInteractor, config: Config):
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
        self._config = config

        self.emulator_json = {}

    def execute(self):
        self.emulator_json = call_emulated(self._contract or "deploy", self._sender, self._data, self._value)
        self.debug(f'emulator returns: {json.dumps(self.emulator_json, sort_keys=True)}')

    def _resize_cost(self) -> int:
        cost = 0

        # Some accounts may not exist at the emulation time
        # Calculate gas for them separately
        accounts_size = [
            a["code_size"] + self._config.contract_extra_space
            for a in self.emulator_json.get("accounts", [])
            if (not a["code_size_current"]) and a["code_size"]
        ]

        if not accounts_size:
            return cost

        accounts_size.append(ACCOUNT_INFO_LAYOUT.sizeof())
        balances = self._solana.get_multiple_rent_exempt_balances_for_size(accounts_size)
        self.debug(f'sizes: {accounts_size}, balances: {balances}')

        for balance in balances[:-1]:
            cost += balances[-1]
            cost += balance

        return cost

    def _tx_size_cost(self) -> int:
        u256_max = int.from_bytes(bytes([0xFF] * 32), "big")

        tx = NeonTx(
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
        msg = rlp.encode(tx)
        return ((len(msg) // ElfParams().holder_msg_size) + 1) * 5000

    @staticmethod
    def _iterative_overhead_cost() -> int:
        last_iteration_cost = 5000
        cancel_cost = 5000

        return last_iteration_cost + cancel_cost

    def estimate(self):
        execution_cost = self.emulator_json.get('used_gas', 0)
        resize_cost = self._resize_cost()
        tx_size_cost = self._tx_size_cost()
        overhead = self._iterative_overhead_cost()

        gas = execution_cost + resize_cost + tx_size_cost + overhead
        extra_gas_pct = self._config.extra_gas_pct
        if extra_gas_pct > 0:
            gas = math.ceil(gas * (1 + extra_gas_pct))
        if gas < 21000:
            gas = 21000

        self.debug(f'execution_cost: {execution_cost}, ' +
                   f'resize_cost: {resize_cost}, ' +
                   f'trx_size_cost: {tx_size_cost}, ' +
                   f'iterative_overhead: {overhead}, ' +
                   f'extra_gas_pct: {extra_gas_pct}, ' +
                   f'estimated gas: {gas}')

        return gas
