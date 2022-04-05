import argparse
import sys

from .account import AccountHandler
from .operator import OperatorHandler
from .info import InfoHandler

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Client command line utility for Neon Proxy.')
    subparsers = parser.add_subparsers(title='command', dest='command', description='valid commands')

    account_handler = AccountHandler.init_args_parser(subparsers)
    operator_handler = OperatorHandler.init_args_parser(subparsers)
    info_handler = InfoHandler.init_args_parser(subparsers)

    args = parser.parse_args()
    if args.command == account_handler.command:
        account_handler.execute(args)
    elif args.command == operator_handler.command:
        operator_handler.execute(args)
    elif args.command == info_handler.command:
        info_handler.execute(args)
    else:
        print(f'Unknown command {args.command}', file=sys.stderr)
