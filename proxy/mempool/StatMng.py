# import abc
# import socket
#
# from neon_py.network import PipePickableDataClient
#
#
# class StatServiceClient(PipePickableDataClient):
#
#     def __init__(self, client_sock: socket.socket):
#         PipePickableDataClient.__init__(self, client_sock=client_sock)
#
#
# class IStatMng(abc.ABC):
#
#     @abc.abstractmethod
#     def on_blocked_account(self):
#         pass
#
#     @abc.abstractmethod
#     def on_version_update(self):
#         pass
#
#     @abc.abstractmethod
#     def on_new_trx(self, sender: str, count: int):
#         pass
#
#     @abc.abstractmethod
#     def on_trx_gone(self, sender: str):
#         pass
#
#
# class StatMidleware():
#
#     def __init__(self):
#         self._stat_mng_client =
#
#
# class StatService()
#
#     def
#
# class StatMng:
#
#     sel
