import sys
import atheris

from random import choice
from random import getrandbits
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


def TestEthgetBlockByHash(data):
    try:
        _ = model.eth_getBlockByNumber(
            tag=int.from_bytes(data, "little"), full=bool(getrandbits(1))
        )
    except RuntimeError:
        None


def main():
    print("Starting...")
    atheris.instrument_all()
    sys.argv.append("-max_len=32")
    atheris.Setup(sys.argv, TestEthgetBlockByHash)
    atheris.Fuzz()


main()
