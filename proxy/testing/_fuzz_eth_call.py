import sys
import atheris

from random import choice
from ._base_fuzz_config import FuzzConfig

from proxy.mempool.mempool_service import MPService
from ..neon_rpc_api_model import NeonRpcApiWorker

global tag
global config
global mempool_service
global model



tag = ["latest", "pending"]
config = FuzzConfig()
mempool_service = MPService(config)
mempool_service.start()
model = NeonRpcApiWorker()


def TestEthCall(data):
    if len(data) < 40:
        return None

    fdp = atheris.FuzzedDataProvider(data)
    from_data = fdp.ConsumeBytes(20)
    to_data = fdp.ConsumeBytes(20)
    call_obj = {"from": "0x" + from_data.hex(), "to": "0x" + to_data.hex()}
    try:
        _ = model.eth_call(call_obj, tag=choice(tag))
    except RuntimeError:
        None


def main():
    print("Starting...")
    atheris.instrument_all()
    sys.argv.append("-max_len=40")
    # Immediately try inputs with size up to max_len.
    sys.argv.append("-len_control=0")
    atheris.Setup(sys.argv, TestEthCall)
    atheris.Fuzz()


main()
