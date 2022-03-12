import base58

from ..environment import EVM_LOADER_ID
from ..indexer.base_db import BaseDB


class SQLCost(BaseDB):
    def __init__(self):
        BaseDB.__init__(self, 'OPERATOR_COST')

    def insert(self, hash, cost, used_gas, sender, to_address, sig, status, reason):
        with self._conn.cursor() as cur:
            cur.execute(f'''
                    INSERT INTO {self._table_name} (hash, cost, used_gas, sender, to_address, sig, status, reason)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ''',
                (hash, cost, used_gas, sender, to_address, sig, status, reason)
            )


operator_cost = SQLCost()


def update_transaction_cost(receipt, eth_trx, extra_sol_trx=False, reason=None):
    cost = receipt['meta']['preBalances'][0] - receipt['meta']['postBalances'][0]
    if eth_trx:
        hash = eth_trx.hash_signed().hex()
        sender = eth_trx.sender()
        to_address = eth_trx.toAddress.hex() if eth_trx.toAddress else "None"
    else:
        hash = None
        sender = None
        to_address = None

    sig = receipt['transaction']['signatures'][0]
    used_gas=None

    tx_info = receipt
    accounts = tx_info["transaction"]["message"]["accountKeys"]
    evm_loader_instructions = []

    for idx, instruction in enumerate(tx_info["transaction"]["message"]["instructions"]):
        if accounts[instruction["programIdIndex"]] == EVM_LOADER_ID:
            evm_loader_instructions.append(idx)

    for inner in (tx_info['meta']['innerInstructions']):
        if inner["index"] in evm_loader_instructions:
            for event in inner['instructions']:
                if accounts[event['programIdIndex']] == EVM_LOADER_ID:
                    used_gas = base58.b58decode(event['data'])[2:10]
                    used_gas = int().from_bytes(used_gas, "little")

    operator_cost.insert(
        hash,
        cost,
        used_gas if used_gas else 0,
        sender,
        to_address,
        sig,
        'extra' if extra_sol_trx else 'ok',
        reason if reason else ''
    )
