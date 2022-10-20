import json
import os
import subprocess
import sys
from typing import List, Optional

import logging
from logged_groups import logged_group, LogMng

from ..common_neon.solana_tx import SolAccount
from ..common_neon.config import Config


@logged_group("neon.Proxy")
class CliBase:
    def __init__(self, config: Config):
        self._config = config

    def run_cli(self, cmd: List[str], data: str = None, **kwargs) -> str:
        self.debug("Calling: " + " ".join(cmd))

        if not data:
            data = ""
        result = subprocess.run(cmd, input=data, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
        if result.stderr is not None:
            print(result.stderr, file=sys.stderr)
        output = result.stdout
        if not output:
            result.check_returncode()
        return output


class SolanaCli(CliBase):
    def call(self, *args):
        try:
            cmd = ["solana",
                   "--url", self._config.solana_url,
                   ] + list(args)
            self.debug("Calling: " + " ".join(cmd))
            return self.run_cli(cmd, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            self.error("ERR: solana error {}".format(err))
            raise


class NeonCli(CliBase):
    EMULATOR_LOGLEVEL = {
        logging.CRITICAL: "off",
        logging.ERROR: "error",
        logging.WARNING: "warn",
        logging.INFO: "info",
        logging.DEBUG: "debug",
        logging.NOTSET: "warn"
    }

    def call(self, *args, data=None):
        try:
            ctx = json.dumps(LogMng.get_logging_context())
            cmd = ["neon-cli",
                   "--commitment=recent",
                   "--url", self._config.solana_url,
                   f"--evm_loader={str(self._config.evm_loader_id)}",
                   f"--logging_ctx={ctx}",
                   f"--loglevel={self._emulator_logging_level}"
                   ]\
                  + (["-vvv"] if self._config.neon_cli_debug_log else [])\
                  + list(args)
            return self.run_cli(cmd, data, timeout=self._config.neon_cli_timeout, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            self.error("ERR: neon-cli error {}".format(err))
            raise

    @property
    def _emulator_logging_level(self):
        level = logging.getLogger("neon.Emulator").getEffectiveLevel()
        cli_level = self.EMULATOR_LOGLEVEL.get(level, "warn")
        return cli_level

    def version(self):
        try:
            cmd = ["neon-cli", "--version"]
            return self.run_cli(cmd, timeout=self._config.neon_cli_timeout, universal_newlines=True).split()[1]
        except subprocess.CalledProcessError as err:
            self.error("ERR: neon-cli error {}".format(err))
            raise
