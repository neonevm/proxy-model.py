import os

from typing import Dict, Any


class DBConfig:
    def __init__(self):
        self._postgres_host = os.environ['POSTGRES_HOST']
        self._postgres_db = os.environ['POSTGRES_DB']
        self._postgres_user = os.environ['POSTGRES_USER']
        self._postgres_password = os.environ['POSTGRES_PASSWORD']

    @property
    def postgres_host(self) -> str:
        return self._postgres_host

    @property
    def postgres_db(self) -> str:
        return self._postgres_db

    @property
    def postgres_user(self) -> str:
        return self._postgres_user

    @property
    def postgres_password(self) -> str:
        return self._postgres_password

    def as_dict(self) -> Dict[str, Any]:
        return {
            # Don't print
            # 'POSTGRES_HOST': self.postgres_host,
            'POSTGRES_DB': self.postgres_db,
            # 'POSTGRES_USER': self.postgres_user,
            # 'POSTGRES_PASSWORD': self.postgres_password
        }
