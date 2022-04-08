from abc import ABC, abstractclassmethod


class IIndexerUser(ABC):

    @abstractclassmethod
    def on_neon_tx_result(self, status):
        ''' on status '''

    @abstractclassmethod
    def on_solana_rpc_status(self, status):
        ''' on status '''

    @abstractclassmethod
    def on_db_status(self, status):
        ''' on status '''
