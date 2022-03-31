from abc import ABC, abstractmethod


class IndexerStatisticsExporter(ABC):

    @abstractmethod
    def stat_commit_tx_sol_spent(self, neon_tx_hash: str, sol_tx_hash: str, sol_spent: int):
        """How many SOLs being spend in Neon transaction per iteration"""

    @abstractmethod
    def stat_commit_tx_steps_bpf(self, neon_tx_hash: str, sol_tx_hash: str, steps: int, bpf: int):
        """How many Steps/BPF cycles was used in each iteration"""

    @abstractmethod
    def stat_commit_tx_count(self, canceled: bool = False):
        """Count of Neon transactions were completed (independent on status)"""

    @abstractmethod
    def stat_commit_count_sol_tx_per_neon_tx(self, type: str):
        """Count of transactions by type(single\iter\iter w holder)"""

    @abstractmethod
    def stat_commit_postgres_availability(self, status: bool):
        """Postgres availability"""

    @abstractmethod
    def stat_commit_solana_rpc_health(self, status: bool):
        """Solana Node status"""
