import asyncio
import socket
import logging
from typing import Any
import multiprocessing as mp


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s %(process)d %(message)s'))
logger.addHandler(handler)

from proxy.common_neon.utils.pickable_data_server import PipePickableDataSrv, PipePickableDataClient, \
                                                         AddrPickableDataSrv, AddrPickableDataClient, \
                                                         PickableDataServerUser


class User(PickableDataServerUser):

    def __init__(self):
        self.counter = 0

    async def on_data_received(self, data: Any):
        self.counter += 1
        print(f"Got data: {data}")
        return {"Result": self.counter}


def pipe_interaction_sample():
    srv_sock, client_sock = socket.socketpair()

    def async_pipe_serv_proc():
        user = User()
        event_loop = asyncio.new_event_loop()
        srv = PipePickableDataSrv(user=user, srv_sock=srv_sock)
        event_loop.create_task(srv.run_server())
        event_loop.run_forever()

    async def async_pipe_client_proc():
        try:
            pk_client = PipePickableDataClient(client_sock=client_sock)
            result = await pk_client.send_data_async({"a": 1})
            print(f"Result is: {result}")
            result = await pk_client.send_data_async({"a": 2})
            print(f"Result is: {result}")
        except BaseException as err:
            print(f"ERROR: {err}")

    srv_proc = mp.Process(target=async_pipe_serv_proc)
    srv_proc.start()

    event_loop = asyncio.new_event_loop()
    event_loop.run_until_complete(async_pipe_client_proc())
    srv_proc.kill()


def addr_interaction_sample():

    def async_addr_serv_proc():
        user = User()
        event_loop = asyncio.new_event_loop()
        srv = AddrPickableDataSrv(user=user, address=('0.0.0.0', 9091))
        event_loop.create_task(srv.run_server())
        event_loop.run_forever()

    srv_proc = mp.Process(target=async_addr_serv_proc)
    srv_proc.start()

    client = AddrPickableDataClient(('localhost', 9091))
    result = client.send_data({"a": 1})
    print(f"Result: {result}")
    result = client.send_data({"a": 2})
    print(f"Result: {result}")
    srv_proc.kill()

#pipe_interaction_sample()
addr_interaction_sample()
