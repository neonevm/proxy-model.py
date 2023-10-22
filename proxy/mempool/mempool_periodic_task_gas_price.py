import abc
from typing import Optional, Dict

from .executor_mng import MPExecutorMng
from .mempool_api import MPGasPriceTokenRequest, MPGasPriceRequest, MPGasPriceResult
from .mempool_periodic_task import MPPeriodicTaskLoop

from ..common_neon.constants import ONE_BLOCK_SEC
from ..common_neon.evm_config import EVMConfig
from ..common_neon.solana_tx import SolPubKey


class IGasPriceUser(abc.ABC):
    @abc.abstractmethod
    def on_gas_price(self, gas_price: MPGasPriceResult) -> None: pass


class MPGasPriceTaskLoop(MPPeriodicTaskLoop[MPGasPriceRequest, MPGasPriceResult]):
    _default_sleep_sec = ONE_BLOCK_SEC * 16

    def __init__(self, executor_mng: MPExecutorMng, user: IGasPriceUser) -> None:
        super().__init__(name='gas-price', sleep_sec=self._default_sleep_sec, executor_mng=executor_mng)
        self._user = user
        self._gas_price: Optional[MPGasPriceResult] = None

    def _submit_request(self) -> None:
        req_id = self._generate_req_id()
        token_dict: Dict[int, SolPubKey] = dict()

        last_update_mapping_sec = 0
        sol_price_acct: Optional[SolPubKey] = None
        if self._gas_price:
            sol_price_acct = self._gas_price.sol_price_account
            last_update_mapping_sec = self._gas_price.last_update_mapping_sec
            token_dict: Dict[int, SolPubKey] = {
                token_price.chain_id: token_price.token_price_account
                for token_price in self._gas_price.token_list
            }

        evm_cfg = EVMConfig()
        token_list = [
            MPGasPriceTokenRequest(
                chain_id=token_info.chain_id,
                token_name=token_info.token_name,
                price_account=token_dict.get(token_info.chain_id, None)
            )
            for token_info in evm_cfg.token_info_list
        ]

        mp_req = MPGasPriceRequest(
            req_id=req_id,
            last_update_mapping_sec=last_update_mapping_sec,
            sol_price_account=sol_price_acct,
            token_list=token_list
        )

        self._submit_request_to_executor(mp_req)

    def _process_error(self, _: MPGasPriceRequest) -> None:
        pass

    async def _process_result(self, _: MPGasPriceRequest, mp_res: MPGasPriceResult) -> None:
        self._gas_price = mp_res
        self._user.on_gas_price(mp_res)
