import os


class DBConfig:
    def __init__(self):
        self._postgres_db = os.environ['POSTGRES_DB']
        self._postgres_user = os.environ['POSTGRES_USER']
        self._postgres_password = os.environ['POSTGRES_PASSWORD']
        self._postgres_host = os.environ['POSTGRES_HOST']

    @property
    def postgres_db(self) -> str:
        return self._postgres_db

    @property
    def postgres_user(self) -> str:
        return self._postgres_user

    @property
    def postgres_password(self) -> str:
        return self._postgres_password

    @property
    def postgres_host(self) -> str:
        return self._postgres_host
