from abc import ABC, abstractmethod


class StatisticsExporter(ABC):

    @abstractmethod
    def stat_commit_request_and_timeout(self, endpoint: str, latency: float):
        """Переместить"""

    @abstractmethod
    def stat_commit_tx_begin(self):
        """Переместить"""

    @abstractmethod
    def stat_commit_tx_end_success(self):
        """Переместить"""

    @abstractmethod
    def stat_commit_tx_end_failed(self, err: Exception):
        """Переместить"""

    @abstractmethod
    def stat_commit_tx_balance_change(self, sol_acc: str, sol_diff: int, neon_acc: str, neon_diff: int):
        """Переместить"""

    @abstractmethod
    def stat_commit_operator_sol_balance(self, operator: str, sol_balance: float):
        """Переместить"""

    @abstractmethod
    def stat_commit_operator_neon_balance(self, sol_acc: str, neon_acc: str, neon_balance: float):
        """Переместить"""

    @abstractmethod
    def stat_commit_create_resource_account(self, account: str, rent: int):
        """Переместить"""

    @abstractmethod
    def stat_commit_gas_parameters(self, gas_price: int, sol_price_usd: float, neon_price_usd: float, operator_fee: float):
        """Переместить"""
