import sys
import atheris

from random import choice
from ._base_fuzz_config import FuzzConfig

from proxy.mempool.mempool_service import MPService
from ..neon_rpc_api_model import NeonRpcApiWorker
from ..common_neon.errors import InvalidParamError

global tag
global config
global mempool_service
global model

tag = ["latest", "pending"]
config = FuzzConfig()
mempool_service = MPService(config)
mempool_service.start()
model = NeonRpcApiWorker()


def TestEthgetBalance(data):
    try:
        _ = model.eth_getBalance(account="0x" + data.hex(), tag=choice(tag))
    except InvalidParamError:
        None


def main():
    print("Starting...")
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestEthgetBalance)
    atheris.Fuzz()


main()
