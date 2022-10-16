import json
import math

from typing import Dict, Any, List
from logged_groups import logged_group

from ..common_neon.emulator_interactor import call_emulated, check_emulated_exit_status
from ..common_neon.elf_params import ElfParams

from ..common_neon.config import Config
from ..common_neon.eth_proto import NeonTx
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_alt_builder import ALTTxBuilder
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_transaction import SolAccount, SolPubKey, SolAccountMeta, SolLegacyTx, SolBlockhash
from ..common_neon.address import NeonAddress


class _GasTxBuilder:
    def __init__(self):
        # This values doesn't used on real network, they are used only to generate temporary data
        holder_key = bytes([
            61, 147, 166, 57, 23, 88, 41, 136, 224, 223, 120, 142, 155, 123, 221, 134,
            16, 102, 170, 82, 76, 94, 95, 178, 125, 232, 191, 172, 103, 157, 145, 190
        ])
        holder = SolAccount.from_secret_key(holder_key)

        operator_key = bytes([
            161, 247, 66, 157, 203, 188, 141, 236, 124, 123, 200, 192, 255, 23, 161, 34,
            116, 202, 70, 182, 176, 194, 195, 168, 185, 132, 161, 142, 203, 57, 245, 90
        ])
        self._signer = SolAccount.from_secret_key(operator_key)
        neon_address = NeonAddress.from_private_key(operator_key)
        self._blockhash = SolBlockhash('4NCYB3kRT8sCNodPNuCZo8VUh4xqpBQxsxed2wd9xaD4')

        self._neon_ix_builder = NeonIxBuilder(self._signer.public_key)
        self._neon_ix_builder.init_iterative(holder.public_key)
        self._neon_ix_builder.init_operator_neon(neon_address)

    def build_tx(self, tx: NeonTx, account_list: List[SolAccountMeta]) -> SolLegacyTx:
        self._neon_ix_builder.init_neon_tx(tx)
        self._neon_ix_builder.init_neon_account_list(account_list)

        tx = SolLegacyTx(instructions=[
            self._neon_ix_builder.make_compute_budget_heap_ix(),
            self._neon_ix_builder.make_compute_budget_cu_ix(),
            self._neon_ix_builder.make_tx_step_from_data_ix(ElfParams().neon_evm_steps, 1)
        ])

        tx.recent_blockhash = self._blockhash
        tx.sign(self._signer)
        return tx

    def neon_tx_len(self) -> int:
        return len(self._neon_ix_builder.holder_msg)


@logged_group("neon.Proxy")
class GasEstimate:
    _tx_builder = _GasTxBuilder()
    _u256_max = int.from_bytes(bytes([0xFF] * 32), "big")

    def __init__(self, config: Config, solana: SolInteractor, request: Dict[str, Any]):
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

        self._account_list: List[SolAccountMeta] = []
        self.emulator_json = {}

    def execute(self):
        emulator_json = call_emulated(self._config, self._contract or "deploy", self._sender, self._data, self._value)
        check_emulated_exit_status(emulator_json)

        self.emulator_json = emulator_json
        self.debug(f'emulator returns: {json.dumps(emulator_json, sort_keys=True)}')

    def _tx_size_cost(self) -> int:
        self.debug('__tx_size_cost 1')
        tx = NeonTx(
            nonce=self._u256_max,
            gasPrice=self._u256_max,
            gasLimit=self._u256_max,
            toAddress=bytes.fromhex(self._contract),
            value=int(self._value, 16),
            callData=bytes.fromhex(self._data),
            v=ElfParams().chain_id * 2 + 35,
            r=0x1820182018201820182018201820182018201820182018201820182018201820,
            s=0x1820182018201820182018201820182018201820182018201820182018201820
        )

        try:
            sol_tx = self._tx_builder.build_tx(tx, self._account_list)
            sol_tx.serialize()  # <- there will be exception
            return 0
        except (Exception, ):
            return ((self._tx_builder.neon_tx_len() // ElfParams().holder_msg_size) + 1) * 5000

    @staticmethod
    def _iterative_overhead_cost() -> int:
        last_iteration_cost = 5000
        cancel_cost = 5000

        return last_iteration_cost + cancel_cost

    def _alt_cost(self) -> int:
        # ALT used by TransactionStepFromAccount, TransactionStepFromAccountNoChainId which have 6 fixed accounts
        acc_cnt = len(self._account_list) + 6
        if acc_cnt > ALTTxBuilder.tx_account_cnt:
            return 5000 * 12  # ALT ix: create + ceil(256/30) extend + deactivate + close
        else:
            return 0

    def _build_account_list(self):
        self._account_list.clear()
        for account in self.emulator_json.get('accounts', []):
            self._account_list.append(SolAccountMeta(SolPubKey(account['account']), False, True))

        for account in self.emulator_json.get('solana_accounts', []):
            self._account_list.append(SolAccountMeta(SolPubKey(account['pubkey']), False, True))

    def estimate(self):
        self._build_account_list()

        execution_cost = self.emulator_json.get('used_gas', 0)

        tx_size_cost = self._tx_size_cost()
        overhead = self._iterative_overhead_cost()
        alt_cost = self._alt_cost()

        gas = execution_cost + tx_size_cost + overhead + alt_cost
        extra_gas_pct = self._config.extra_gas_pct
        if extra_gas_pct > 0:
            gas = math.ceil(gas * (1 + extra_gas_pct))
        if gas < 21000:
            gas = 21000

        self.debug(
            f'execution_cost: {execution_cost}, '
            f'tx_size_cost: {tx_size_cost}, '
            f'iterative_overhead: {overhead}, '
            f'alt_cost: {alt_cost}, '
            f'extra_gas_pct: {extra_gas_pct}, '
            f'estimated gas: {gas}'
        )

        return gas
