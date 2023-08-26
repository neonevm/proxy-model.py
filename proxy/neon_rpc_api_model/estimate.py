import logging
import math

from typing import Dict, Any, List, Optional

from ..common_neon.address import NeonAddress
from ..common_neon.config import Config
from ..common_neon.elf_params import ElfParams
from ..common_neon.emulator_interactor import call_emulated, check_emulated_exit_status
from ..common_neon.utils.eth_proto import NeonTx
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_alt_limit import ALTLimit
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_tx import SolAccount, SolPubKey, SolAccountMeta, SolBlockHash, SolTxSizeError
from ..common_neon.solana_tx_legacy import SolLegacyTx


LOG = logging.getLogger(__name__)


class _GasTxBuilder:
    def __init__(self):
        # This values doesn't used on real network, they are used only to generate temporary data
        holder_key = bytes([
            61, 147, 166, 57, 23, 88, 41, 136, 224, 223, 120, 142, 155, 123, 221, 134,
            16, 102, 170, 82, 76, 94, 95, 178, 125, 232, 191, 172, 103, 157, 145, 190
        ])
        holder = SolAccount.from_seed(holder_key)

        operator_key = bytes([
            161, 247, 66, 157, 203, 188, 141, 236, 124, 123, 200, 192, 255, 23, 161, 34,
            116, 202, 70, 182, 176, 194, 195, 168, 185, 132, 161, 142, 203, 57, 245, 90
        ])
        self._signer = SolAccount.from_seed(operator_key)
        neon_address = NeonAddress.from_private_key(operator_key)
        self._block_hash = SolBlockHash.from_string('4NCYB3kRT8sCNodPNuCZo8VUh4xqpBQxsxed2wd9xaD4')

        self._neon_ix_builder = NeonIxBuilder(self._signer.pubkey())
        self._neon_ix_builder.init_iterative(holder.pubkey())
        self._neon_ix_builder.init_operator_neon(neon_address)

    def build_tx(self, tx: NeonTx, account_list: List[SolAccountMeta]) -> SolLegacyTx:
        self._neon_ix_builder.init_neon_tx(tx)
        self._neon_ix_builder.init_neon_account_list(account_list)

        tx = SolLegacyTx(
            name='Estimate',
            ix_list=[
                self._neon_ix_builder.make_compute_budget_heap_ix(),
                self._neon_ix_builder.make_compute_budget_cu_ix(),
                self._neon_ix_builder.make_tx_step_from_data_ix(ElfParams().neon_evm_steps, 1)
            ]
        )

        tx.recent_block_hash = self._block_hash
        tx.sign(self._signer)
        return tx

    @property
    def len_neon_tx(self) -> int:
        return len(self._neon_ix_builder.holder_msg)


class GasEstimate:
    _small_gas_limit = 30_000  # openzeppelin size check
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
        self._elf_params = ElfParams()

        self._cached_tx_cost_size: Optional[int] = None
        self._cached_alt_cost: Optional[int] = None

        self._account_list: List[SolAccountMeta] = list()
        self.emulator_json = dict()

    def execute(self):
        emulator_json = call_emulated(self._config, self._contract or "deploy", self._sender, self._data, self._value)
        LOG.debug(f'emulator returns: {emulator_json}')
        check_emulated_exit_status(emulator_json)

        self.emulator_json = emulator_json

    def _tx_size_cost(self) -> int:
        if self._cached_tx_cost_size is not None:
            return self._cached_tx_cost_size

        neon_tx = NeonTx(
            nonce=self._u256_max,
            gasPrice=self._u256_max,
            gasLimit=self._u256_max,
            toAddress=bytes.fromhex(self._contract),
            value=int(self._value, 16),
            callData=bytes.fromhex(self._data),
            v=self._elf_params.chain_id * 2 + 35,
            r=0x1820182018201820182018201820182018201820182018201820182018201820,
            s=0x1820182018201820182018201820182018201820182018201820182018201820
        )

        self._cached_tx_cost_size = 0
        try:
            sol_tx = self._tx_builder.build_tx(neon_tx, self._account_list)
            sol_tx.serialize()  # <- there will be exception about size

            if not self._contract:  # deploy case
                pass
            elif self._execution_cost() < self._small_gas_limit:
                return self._cached_tx_cost_size
        except SolTxSizeError:
            pass
        except BaseException as exc:
            LOG.debug('Error during pack solana tx', exc_info=exc)

        self._cached_tx_cost_size = self._holder_tx_cost(self._tx_builder.len_neon_tx)
        return self._cached_tx_cost_size

    def _holder_tx_cost(self, neon_tx_len: int) -> int:
        return ((neon_tx_len // self._elf_params.holder_msg_size) + 1) * 5000

    def _execution_cost(self) -> int:
        return self.emulator_json.get('used_gas', 0)

    @staticmethod
    def _iterative_overhead_cost() -> int:
        """
        if the transaction fails on the simple execution in one iteration,
        it is executed in iterative mode to store the Neon receipt on Solana
        """
        last_iteration_cost = 5000
        cancel_cost = 5000
        return last_iteration_cost + cancel_cost

    def _alt_cost(self) -> int:
        """
        Costs to create->extend->deactivate->close an Address Lookup Table
        """
        if self._cached_alt_cost is not None:
            return self._cached_alt_cost

        # ALT is used by TransactionStepFromAccount, TransactionStepFromAccountNoChainId which have 6 fixed accounts
        acc_cnt = len(self._account_list) + 6
        if acc_cnt > ALTLimit.max_tx_account_cnt:
            self._cached_alt_cost = 5000 * 12  # ALT ix: create + ceil(256/30) extend + deactivate + close
        else:
            self._cached_alt_cost = 0

        return self._cached_alt_cost

    def _build_account_list(self):
        self._account_list.clear()
        for account in self.emulator_json.get('accounts', []):
            self._account_list.append(SolAccountMeta(SolPubKey.from_string(account['account']), False, True))

        for account in self.emulator_json.get('solana_accounts', []):
            self._account_list.append(SolAccountMeta(SolPubKey.from_string(account['pubkey']), False, True))

    def estimate(self):
        self._cached_tx_cost_size = None
        self._cached_alt_cost = None

        self._build_account_list()

        execution_cost = self._execution_cost()
        tx_size_cost = self._tx_size_cost()
        overhead_cost = self._iterative_overhead_cost()
        alt_cost = self._alt_cost()

        # Ethereum wallets don't accept gas limit less than 21000
        gas = max(execution_cost + tx_size_cost + overhead_cost + alt_cost, 21000)

        LOG.debug(
            f'execution_cost: {execution_cost}, '
            f'tx_size_cost: {tx_size_cost}, '
            f'iterative_overhead_cost: {overhead_cost}, '
            f'alt_cost: {alt_cost}, '
            f'estimated gas: {gas}'
        )

        return gas
