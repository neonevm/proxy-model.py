import sys
import atheris

from random import randint
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


def TestEthgetLogs(data):
    if len(data) < 148:
        return None

    fdp = atheris.FuzzedDataProvider(data)
    length = randint(0, 32)
    from_block = "0x" + fdp.ConsumeBytes(32)[:length].hex()
    to_block = "0x" + fdp.ConsumeBytes(32)[:length].hex()
    adress = "0x" + fdp.ConsumeBytes(20).hex()
    topics = "0x" + fdp.ConsumeBytes(32).hex()
    block_hash = "0x" + fdp.ConsumeBytes(32).hex()

    obj = {
        "fromBlock": from_block,
        "toBlock": to_block,
        "address": adress,
        "topics": topics,
        "blockHash": block_hash,
    }

    try:
        _ = model.eth_getLogs(obj)
    except RuntimeError:
        None


def main():
    print("Starting...")
    atheris.instrument_all()
    sys.argv.append("-max_len=148")
    # Immediately try inputs with size up to max_len.
    sys.argv.append("-len_control=0")
    atheris.Setup(sys.argv, TestEthgetLogs)
    atheris.Fuzz()


main()
