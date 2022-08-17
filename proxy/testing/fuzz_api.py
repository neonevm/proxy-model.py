import sys
import atheris

from ..neon_rpc_api_model import NeonRpcApiWorker


def TestEthgetBalance(data, data2):
    try:
        model = NeonRpcApiWorker()
        _ = model.eth_getBalance(account=data, tag=data2)
    except RuntimeError:
        None


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestEthgetBalance)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
