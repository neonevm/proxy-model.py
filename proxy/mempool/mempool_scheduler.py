from sortedcontainers import SortedList
from proxy.mempool.mempool_api import MPTxRequest


class Record:
    def __init__(self, tx_signature, tx_sender, tx_nonce, tx_gas_price, request):
        self.signature = tx_signature
        self.sender = tx_sender
        self.nonce = tx_nonce
        self.gas_price = tx_gas_price
        self.request = request

    def __eq__(self, other):
        return self.signature == other.signature

    def __lt__(self, other):
        if self.sender == other.sender:
            if self.nonce == other.nonce:
                return self.gas_price > other.gas_price
            return self.nonce < other.nonce
        return self.gas_price > other.gas_price


class MPNeonTxScheduler:
    def __init__(self) -> None:
        self._requests = SortedList()

    def add_tx(self, mp_request: MPTxRequest):
        self._requests.add(Record(mp_request.signature, mp_request.neon_tx.sender(), mp_request.neon_tx.nonce, mp_request.neon_tx.gasPrice, mp_request))

    def get_tx_for_execution(self):
        try:
            return self._requests.pop(0).request
        except:
            return None
