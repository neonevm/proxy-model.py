import sys
import atheris

from random import choice
from proxy.common_neon.config import Config

from proxy.mempool.mempool_service import MPService
from ..neon_rpc_api_model import NeonRpcApiWorker


global config
global mempool_service
global model


config = Config()
mempool_service = MPService(config)
mempool_service.start()
model = NeonRpcApiWorker()


def TestEthgetTransactionReceipt(data):
    if len(data) < 32:
        return None
    try:
        _ = model.eth_getTransactionReceipt(neon_tx_sig='0x' + data.hex())
    except RuntimeError:
        None


def main():
    print("Starting...")
    atheris.instrument_all()
    sys.argv.append("-max_len=32")
    # Immediately try inputs with size up to max_len.
    sys.argv.append("-len_control=0")
    atheris.Setup(sys.argv, TestEthgetTransactionReceipt)
    atheris.Fuzz()


main()
