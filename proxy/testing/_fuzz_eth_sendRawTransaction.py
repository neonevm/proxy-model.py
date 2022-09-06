import sys
import atheris

from random import choice
from ._base_fuzz_config import FuzzConfig
from proxy.common_neon.eth_proto import InvalidTrx

from proxy.mempool.mempool_service import MPService
from ..neon_rpc_api_model import NeonRpcApiWorker
from ..common_neon.errors import InvalidParamError


global config
global mempool_service
global model


config = Config()
mempool_service = MPService(config)
mempool_service.start()
model = NeonRpcApiWorker()


def TestEthsendRawTransaction(data):
    try:
        _ = model.eth_sendRawTransaction(raw_tx="0x" + data.hex())
    except InvalidTrx:
        None
    except InvalidParamError:
        None
    except RuntimeError:
        None


def main():
    print("Starting...")
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestEthsendRawTransaction)
    atheris.Fuzz()


main()
