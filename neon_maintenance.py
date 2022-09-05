import argparse

from neon_py.network import AddrPickableDataClient
from neon_py.maintenance_api import MaintenanceCommand, MaintenanceRequest, ReplicationRequest, Peer
from neon_py.utils import gen_unique_id
from logged_groups import logged_group
from typing import List


@logged_group("neon.Maintenance")
class MaintenanceClient:

    def __init__(self, address):
        self.address = address
        self._client = AddrPickableDataClient(address)

    def suspend(self):
        result = self._client.send_data(MaintenanceRequest(req_id=gen_unique_id(), command=MaintenanceCommand.SuspendMemPool))
        self.info(f"The suspend command has been sent to the MemPool: {self.address}, result: {result}")

    def resume(self):
        result = self._client.send_data(MaintenanceRequest(req_id=gen_unique_id(), command=MaintenanceCommand.ResumeMemPool))
        self.info(f"The resume command has been sent to the MemPool: {self.address}, result: {result}")

    def replicate(self, peers: List[Peer]):
        request = ReplicationRequest(peers=peers)
        result = self._client.send_data(request)
        self.info(f"The replicate command has been sent to the MemPool: {self.address}, result: {result}")


def main():

    args = get_maintenance_args()

    maintenance_client = MaintenanceClient((args.host, args.port))
    if args.command == "suspend":
        maintenance_client.suspend()
    elif args.command == "resume":
        maintenance_client.resume()
    elif args.command == "replicate":
        peers = [Peer(*(peer_info.split(":"))) for peer_info in args.peers]
        maintenance_client.replicate(peers)


def get_maintenance_args():

    examples = """
Examples:

suspend:

    neon_maintenance.py --port 8092 suspend

resume:

    neon_maintenance.py --host localhost --port 9092 resume

replicate:

    python3 neon_maintenance.py replicate proxy-replica:9092
\x0D"""

    parser = argparse.ArgumentParser(prog="neon_maintenance", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=examples)
    parser.add_argument("--host", type=str, required=False, default="127.0.0.1", help="Neon Proxy maintenance host to connect")
    parser.add_argument("--port", type=int, required=False, default=9092, help="Neon Proxy maintenance port to connect")
    subparsers = parser.add_subparsers(dest="command", help="subcommand help")
    subparsers.add_parser("suspend", help="suspend Neon Proxy mempool")
    subparsers.add_parser("resume", help="resume Neon Proxy mempool")
    parser_replicate = subparsers.add_parser("replicate", help="replicate Neon Proxy mempool")
    parser_replicate.add_argument("peers", nargs="+", help="other Neon Proxy peer address list to replicate to")
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    main()


