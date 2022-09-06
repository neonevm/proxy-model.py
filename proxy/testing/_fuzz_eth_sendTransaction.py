import sys
import atheris

from random import choice
from ._base_fuzz_config import FuzzConfig
from proxy.common_neon.eth_proto import InvalidTrx

from proxy.mempool.mempool_service import MPService
from ..neon_rpc_api_model import NeonRpcApiWorker
from ..common_neon.errors import EthereumError


global config
global mempool_service
global model


config = FuzzConfig()
mempool_service = MPService(config)
mempool_service.start()
model = NeonRpcApiWorker()


def TestEthsendTransaction(data):
    if len(data) < 40:
        return None

    fdp = atheris.FuzzedDataProvider(data)
    from_data = fdp.ConsumeBytes(20)
    to_data = fdp.ConsumeBytes(20)
    try:
        tx = {"from": "0x" + from_data.hex(), "to": "0x" + to_data.hex()}
        _ = model.eth_sendTransaction(tx)
    except EthereumError:
        None


def main():
    print("Starting...")
    atheris.instrument_all()
    sys.argv.append("-max_len=40")
    # Immediately try inputs with size up to max_len.
    sys.argv.append("-len_control=0")
    atheris.Setup(sys.argv, TestEthsendTransaction)
    atheris.Fuzz()


main()
