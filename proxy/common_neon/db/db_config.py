import os

from typing import Dict, Any


class DBConfig:
    _postgres_host_name = 'POSTGRES_HOST'
    _postgres_db_name = 'POSTGRES_DB'
    _postgres_user_name = 'POSTGRES_USER'
    _postgres_password_name = 'POSTGRES_PASSWORD'
    _postgres_null_value = '<NULL>'

    def __init__(self):
        self._postgres_host = os.environ.get(self._postgres_host_name, self._postgres_null_value)
        self._postgres_db = os.environ.get(self._postgres_db_name, self._postgres_null_value)
        self._postgres_user = os.environ.get(self._postgres_user_name, self._postgres_null_value)
        self._postgres_password = os.environ.get(self._postgres_password_name, self._postgres_null_value)
        self._postgres_timeout = int(os.environ.get('POSTGRES_TIMEOUT', '0'), 10)

    def validate_db_config(self) -> None:
        value_dict = {
            self._postgres_host_name: self._postgres_host,
            self._postgres_db_name: self._postgres_db,
            self._postgres_user_name: self._postgres_user,
            self._postgres_password_name: self._postgres_password
        }

        for key, value in value_dict.items():
            if value == self._postgres_null_value:
                raise ValueError(f'{key} is not specified')

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

    @property
    def postgres_timeout(self):
        return self._postgres_timeout

    def as_dict(self) -> Dict[str, Any]:
        return {
            # Don't print private configuration
            # 'POSTGRES_HOST': self.postgres_host,
            'POSTGRES_DB': self.postgres_db,
            # 'POSTGRES_USER': self.postgres_user,
            # 'POSTGRES_PASSWORD': self.postgres_password

            'POSTGRES_TIMEOUT': self.postgres_timeout,
        }
