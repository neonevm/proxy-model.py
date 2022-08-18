import sys
import atheris

from random import choice
from ..neon_rpc_api_model import NeonRpcApiWorker

global tag
tag = ["latest", "pending"]


def TestEthgetBalance(data):
    try:
        model = NeonRpcApiWorker()
        _ = model.eth_getBalance(account="0x" + data.hex(), tag=choice(tag))
    except RuntimeError:
        None


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestEthgetBalance)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
