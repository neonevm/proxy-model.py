import sys
import atheris

from random import choice
from proxy.common_neon.config import Config

from proxy.mempool.mempool_service import MPService
from ..neon_rpc_api_model import NeonRpcApiWorker

global tag
global config
global mempool_service
global model

tag = ["latest", "pending"]
config = Config()
mempool_service = MPService(config)
mempool_service.start()
model = NeonRpcApiWorker()


def TestEthgetBalance(data):
    if len(data) < 20:
        return None
    try:
        _ = model.eth_getTransactionCount(account="0x" + data.hex(), tag=choice(tag))
    except RuntimeError:
        None


def main():
    print("Starting...")
    atheris.instrument_all()
    sys.argv.append("-max_len=20")
    # Immediately try inputs with size up to max_len.
    sys.argv.append("-len_control=0")
    atheris.Setup(sys.argv, TestEthgetBalance)
    atheris.Fuzz()


main()
