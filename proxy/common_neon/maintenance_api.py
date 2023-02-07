from enum import IntEnum
from dataclasses import dataclass, field
from typing import List, Any, Optional, Tuple
from .utils.utils import gen_unique_id


class MaintenanceCommand(IntEnum):
    SuspendMemPool = 0,
    ResumeMemPool = 1,
    ReplicateRequests = 2,
    ReplicateTxsBunch = 3,
    Dummy = -1


@dataclass
class MaintenanceRequest:
    command: MaintenanceCommand = field(default=MaintenanceCommand.Dummy)
    req_id: str = field(default_factory=gen_unique_id)


@dataclass
class Peer:
    host: str
    port: int

    @property
    def address(self) -> Tuple[str, int]:
        return self.host, self.port


@dataclass
class ReplicationRequest(MaintenanceRequest):
    peers: List[Peer] = field(default_factory=list)

    def __post_init__(self):
        self.command = MaintenanceCommand.ReplicateRequests


@dataclass
class ReplicationBunch(MaintenanceRequest):

    sender_addr: Optional[str] = None
    mp_tx_requests: Optional[List[Any]] = None

    def __post_init__(self):
        self.command = MaintenanceCommand.ReplicateTxsBunch

