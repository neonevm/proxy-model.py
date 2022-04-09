from proxy.environment import EVM_LOADER_ID, SOLANA_URL
from .indexer import Indexer, NeonTxResult
from .indexer_app_interface import IIndexerUser
from proxy.statistics_exporter.prometheus_indexer_exporter import IndexerStatistics
from logged_groups import logged_group


@logged_group("neon.Indexer")
class IndexerApp(IIndexerUser):

    def __init__(self, solana_url: str):
        self.neon_statistics = IndexerStatistics()
        indexer = Indexer(solana_url, self)
        indexer.run()

    def on_neon_tx_result(self, neon_tx_result: NeonTxResult):
        neon_tx_hash = neon_tx_result.neon_tx.sign
        neon_income = int(neon_tx_result.neon_res.gas_used, 0) * int(neon_tx_result.neon_tx.gas_price, 0)
        for sign_info, cost_info in zip(neon_tx_result.used_ixs, neon_tx_result.ixs_cost):
            sol_tx_hash = sign_info.sign
            self.neon_statistics.stat_commit_tx_sol_spent(neon_tx_hash, sol_tx_hash, cost_info.sol_spent)
            self.neon_statistics.stat_commit_tx_steps_bpf(neon_tx_hash, sol_tx_hash, sign_info.steps, cost_info.bpf)
        if neon_tx_result.holder_account != '':
            tx_type = 'holder'
        elif neon_tx_result.storage_account != '':
            tx_type = 'iterative'
        else:
            tx_type = 'single'
        self.neon_statistics.stat_commit_tx_count(neon_tx_result.neon_res.status == '0x0')
        self.neon_statistics.stat_commit_tx_neon_income(neon_tx_hash, neon_income)
        self.neon_statistics.stat_commit_count_sol_tx_per_neon_tx(tx_type, len(neon_tx_result.used_ixs))

    def on_db_status(self, neon_db_status: bool):
        self.neon_statistics.stat_commit_postgres_availability(neon_db_status)

    def on_solana_rpc_status(self, solana_status: bool):
        self.neon_statistics.stat_commit_solana_rpc_health(solana_status)


@logged_group("neon.Indexer")
def run_indexer(solana_url, *, logger):
    logger.info(f"""Running indexer with params:
        solana_url: {solana_url},
        evm_loader_id: {EVM_LOADER_ID}""")

    IndexerApp(solana_url)


if __name__ == "__main__":
    solana_url = SOLANA_URL
    run_indexer(solana_url)
