from typing import List, Tuple
from proxy.common_neon.config import IConfig
from proxy.common_neon.eth_proto import Trx
from proxy.common_neon.solana_interactor import SolanaInteractor
from proxy.common_neon.utils.utils import NeonTxInfo, NeonTxResultInfo
from proxy.memdb.memdb import MemDB


class MPNeonTXSubmitter:
    def __init__(self, config: IConfig):
        self._config = config
        self._solana = SolanaInteractor(self._config.get_solana_url())
        self._db = MemDB(self._solana)

    def submit_tx_into_db(self, neon_tx: Trx, tx_result: Tuple[NeonTxResultInfo, List[str]]):
        neon_res: NeonTxResultInfo = tx_result[0]
        sign_list: List[str] = tx_result[1]
        neon_tx_info: NeonTxInfo = NeonTxInfo()
        neon_tx_info.init_from_eth_tx(neon_tx)
        self._db.submit_transaction(neon_tx_info, neon_res, sign_list)
