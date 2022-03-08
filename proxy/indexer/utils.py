from __future__ import annotations

import statistics

from solana.publickey import PublicKey
from logged_groups import logged_group
from typing import Dict, Union, Callable

from ..common_neon.address import ether2program
from ..common_neon.layouts import STORAGE_ACCOUNT_INFO_LAYOUT, CODE_ACCOUNT_INFO_LAYOUT, ACCOUNT_INFO_LAYOUT
from ..common_neon.solana_interactor import SolanaInteractor

from ..environment import INDEXER_LOG_SKIP_COUNT



def check_error(trx):
    if 'meta' in trx and 'err' in trx['meta'] and trx['meta']['err'] is not None:
        return True
    return False


class SolanaIxSignInfo:
    def __init__(self, sign: str, slot: int, idx: int):
        self.sign = sign  # Solana transaction signature
        self.slot = slot  # Solana block slot
        self.idx  = idx   # Instruction index
        self.steps = None # Instruction index

    def __str__(self):
        return f'{self.slot} {self.sign} {self.idx}'

    def __hash__(self):
        return hash((self.sign, self.slot, self.idx))

    def __eq__(self, other):
        return (self.sign, self.slot, self.idx) == (other.sign, other.slot, other.idx)

    def get_req_id(self):
        return f"{self.idx}{self.sign}"[:7]

    def set_steps(self, steps: int):
        self.steps = steps


class CostInfo:
    def __init__(self, sign: str, tx: dict, program: PublicKey):
        self.sign = sign
        self.operator = None
        self.sol_spent = None
        self.bpf = None
        self.heap = None
        self.token_income = None
        if tx:
            self.setup(tx, program)

    def setup(self, tx: dict, program: PublicKey):
        def bpf_log(program, msg_words: list[str]):
            if len(msg_words) >= 7 and\
                msg_words[0] == 'Program' and\
                msg_words[1] == str(program) and\
                msg_words[2] == 'consumed' and\
                msg_words[4] == 'of' and\
                msg_words[6] == 'compute' and\
                msg_words[7] == 'units':
                return int(log_words[3])
            return None
        def heap_log(msg_words: list[str]):
            if len(msg_words) >= 5 and\
                msg_words[0] == 'Program' and\
                msg_words[1] == "log:" and\
                msg_words[2] == 'Total' and\
                msg_words[3] == 'memory' and\
                msg_words[4] == 'occupied:':
                return int(log_words[5])
            return None

        self.operator = tx['transaction']['message']['accountKeys'][0]
        self.sol_spent = tx['meta']['preBalances'][0] - tx['meta']['postBalances'][0]
        for log in tx['meta']['logMessages']:
            log_words = log.split()
            bpf = bpf_log(program, log_words)
            heap = heap_log(log_words)
            if bpf:
                self.bpf = max(self.bpf, bpf) if self.bpf else bpf
            if heap:
                self.heap = max(self.heap, heap) if self.heap else heap

        pre_token = 0
        post_token = 0
        for balance in tx['meta']['preTokenBalances']:
            if balance['owner'] == self.operator:
                pre_token = int(balance["uiTokenAmount"]["amount"])
        for balance in tx['meta']['postTokenBalances']:
            if balance['owner'] == self.operator:
                post_token = int(balance["uiTokenAmount"]["amount"])
        self.token_income = post_token - pre_token


@logged_group("neon.Indexer")
def get_accounts_from_storage(solana: SolanaInteractor, storage_account, *, logger):
    info = solana.get_account_info(storage_account, length=0)
    # logger.debug("\n{}".format(json.dumps(result, indent=4, sort_keys=True)))

    if info is None:
        raise Exception(f"Can't get information about {storage_account}")

    if info.tag == 30:
        logger.debug("Not empty storage")

        acc_list = []
        storage = STORAGE_ACCOUNT_INFO_LAYOUT.parse(info.data[1:])
        offset = 1 + STORAGE_ACCOUNT_INFO_LAYOUT.sizeof()
        for _ in range(storage.accounts_len):
            writable = (info.data[offset] > 0)
            offset += 1

            some_pubkey = PublicKey(info.data[offset:offset + 32])
            acc_list.append(str(some_pubkey))
            offset += 32

            acc_list.append((writable, str(some_pubkey)))

        return acc_list
    else:
        logger.debug("Empty")
        return None


@logged_group("neon.Indexer")
def get_accounts_by_neon_address(solana: SolanaInteractor, neon_address, *, logger):
    pda_address, _nonce = ether2program(neon_address)
    info = solana.get_account_info(pda_address, length=0)
    if info is None:
        logger.debug(f"account_info is None for pda_address({pda_address})")
        return None, None
    if len(info.data) < ACCOUNT_INFO_LAYOUT.sizeof():
        logger.debug(f"{len(info.data)} < {ACCOUNT_INFO_LAYOUT.sizeof()}")
        return None, None
    account = ACCOUNT_INFO_LAYOUT.parse(info.data)
    code_account = None
    if account.code_account != [0]*32:
        code_account = str(PublicKey(account.code_account))
    return pda_address, code_account


@logged_group("neon.Indexer")
def get_code_from_account(solana: SolanaInteractor, address, *, logger):
    code_account_info = solana.get_account_info(address, length=0)
    if code_account_info is None:
        logger.debug(f"code_account_info is None for code_address({address})")
        return None
    if len(code_account_info.data) < CODE_ACCOUNT_INFO_LAYOUT.sizeof():
        return None
    storage = CODE_ACCOUNT_INFO_LAYOUT.parse(code_account_info.data)
    offset = CODE_ACCOUNT_INFO_LAYOUT.sizeof()
    if len(code_account_info.data) < offset + storage.code_size:
        return None
    return '0x' + code_account_info.data[offset:][:storage.code_size].hex()


class MetricsToLogBuff:
    def __init__(self):
        self._reset()

    def _reset(self):
        self.counter = 0
        self.items_list = {}
        self.items_latest = {}

    def print(self, logger: Callable[[str], None], list_params: Dict[str, Union[int, float]], latest_params: Dict[str, int]):
        for key, value in list_params.items():
            metric_list = self.items_list.setdefault(key, [])
            metric_list.append(value)
        for key, value in latest_params.items():
            self.items_latest[key] = value
        self.counter += 1

        if self.counter % INDEXER_LOG_SKIP_COUNT != 0:
            return

        msg = ''
        for key, value_list in self.items_list.items():
            msg += f' {key} avg: {statistics.mean(value_list):.2f}'
            msg += f' min: {min(value_list):.2f}'
            msg += f' max: {max(value_list):.2f};'
        for key, value in self.items_latest.items():
            msg += f' {key}: {value};'
        logger(msg)
        self._reset()
