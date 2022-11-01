from .data import NeonMethodData, NeonGasPriceData, NeonTxBeginData, NeonTxEndData
from .data import NeonOpResStatData, NeonOpResListData, NeonExecutorStatData
from .middleware import StatClient, stat_method


class ProxyStatClient(StatClient):
    @stat_method
    def commit_request_and_timeout(self, method_stat: NeonMethodData): pass

    @stat_method
    def commit_tx_add(self): pass

    @stat_method
    def commit_tx_begin(self, begin_stat: NeonTxBeginData): pass

    @stat_method
    def commit_tx_end(self, end_stat: NeonTxEndData): pass

    @stat_method
    def commit_op_res_list(self, res_list: NeonOpResListData): pass

    @stat_method
    def commit_op_res_stat(self, res_stat: NeonOpResStatData): pass

    @stat_method
    def commit_executor_stat(self, exec_stat: NeonExecutorStatData): pass

    @stat_method
    def commit_gas_price(self, gas_stat: NeonGasPriceData): pass
