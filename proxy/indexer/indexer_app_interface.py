from abc import ABC, abstractmethod


class IIndexerUser(ABC):

    @abstractmethod
#    def on_neon_tx_result(self, result: NeonTxStatInfo):
    def on_neon_tx_result(self, result):
        """On Neon transaction result """

    @abstractmethod
    def on_solana_rpc_status(self, status):
        """On Solana status"""

    @abstractmethod
    def on_db_status(self, status):
        """On Neon database status"""
