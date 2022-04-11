from proxy.environment import EVM_LOADER_ID, SOLANA_URL
from .data import NeonTxStatData
from .indexer import Indexer
from .indexer_app_interface import IIndexerUser
from proxy.statistics_exporter.prometheus_indexer_exporter import IndexerStatistics
from logged_groups import logged_group


@logged_group("neon.Indexer")
class IndexerApp(IIndexerUser):

    def __init__(self, solana_url: str):
        self.neon_statistics = IndexerStatistics()
        indexer = Indexer(solana_url, self)
        indexer.run()

    def on_neon_tx_result(self, tx_stat: NeonTxStatData):
        for instruction_info in tx_stat.instructions:
            sol_tx_hash, sol_spent, steps, bpf = instruction_info
            self.neon_statistics.stat_commit_tx_sol_spent(tx_stat.neon_tx_hash, sol_tx_hash, sol_spent)
            self.neon_statistics.stat_commit_tx_steps_bpf(tx_stat.neon_tx_hash, sol_tx_hash, steps, bpf)
        self.neon_statistics.stat_commit_tx_count(tx_stat.is_canceled)
        self.neon_statistics.stat_commit_tx_neon_income(tx_stat.neon_tx_hash, tx_stat.neon_income)
        self.neon_statistics.stat_commit_count_sol_tx_per_neon_tx(tx_stat.tx_type, len(tx_stat.instructions))

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
