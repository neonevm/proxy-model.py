from logged_groups import logged_group
import asyncio
from multiprocessing import Process

from ..common_neon.config import IConfig

@logged_group("neon.Background")
class BackgroundService:

    def __init__(self, config: IConfig):
        self.event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.event_loop)
        self._process = Process(target=self.run)
        self._config = config

    def start(self):
        self.info("Run background process")
        self._process.start()

    def run(self):
        try:
            self.event_loop.run_forever()
        except Exception as err:
            self.error(f"Failed to run background_service: {err}")
