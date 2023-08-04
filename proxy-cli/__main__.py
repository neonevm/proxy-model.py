import argparse
import sys

from .account import AccountHandler
from .info import InfoHandler
from .holder import HolderHandler
from .neon import NeonHandler


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Client command line utility for Neon Proxy.')
    subparsers = parser.add_subparsers(title='command', dest='command', description='valid commands')

    account_handler = AccountHandler.init_args_parser(subparsers)
    info_handler = InfoHandler.init_args_parser(subparsers)
    holder_handler = HolderHandler.init_args_parser(subparsers)
    neon_handler = NeonHandler.init_args_parser(subparsers)

    args = parser.parse_args()
    if args.command == account_handler.command:
        account_handler.execute(args)
    elif args.command == info_handler.command:
        info_handler.execute(args)
    elif args.command == holder_handler.command:
        if args.subcommand == 'list':
            args.subcommand = 'holder-accounts'
            info_handler.execute(args)
        else:
            holder_handler.execute(args)
    elif args.command == neon_handler.command:
        if args.subcommand == 'list':
            args.subcommand = 'neon-accounts'
            info_handler.execute(args)
        else:
            neon_handler.execute(args)
    else:
        print(f'Unknown command {args.command}', file=sys.stderr)
