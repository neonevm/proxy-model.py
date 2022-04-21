from logged_groups import logged_group

from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.config import IConfig
from ..memdb.memdb import MemDB

# TODO: NeonTxSender should be moved out from there
from .transaction_sender import NeonTxSender
from .operator_resource_list import OperatorResourceList
from .mempool_api import MemPoolTxRequest


@logged_group("neon.MemPool")
class MemPoolTxExecutor:

    def __init__(self, config: IConfig):

        self._solana = SolanaInteractor(config.get_solana_url())
        self._db = MemDB(self._solana)
        self._config = config

    def execute_neon_tx(self, mempool_tx_request: MemPoolTxRequest):
        neon_tx = mempool_tx_request.neon_tx
        neon_tx_cfg = mempool_tx_request.neon_tx_cfg
        emulating_result = mempool_tx_request.emulating_result
        emv_step_count = self._config.get_evm_count()
        tx_sender = NeonTxSender(self._db, self._solana, neon_tx, steps=emv_step_count)
        with OperatorResourceList(tx_sender):
            tx_sender.execute(neon_tx_cfg, emulating_result)
