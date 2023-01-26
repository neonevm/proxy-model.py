import json
import threading
import subprocess
import sys
from typing import List

import logging

from ..common_neon.config import Config


LOG = logging.getLogger(__name__)


class CliBase:
    def __init__(self, config: Config):
        self._config = config

    def run_cli(self, cmd: List[str], data: str = None, **kwargs) -> str:
        LOG.debug("Calling: " + " ".join(cmd))

        if not data:
            data = ""
        LOG.debug(f"data: {data}, len: {len(data)}")

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
            LOG.debug("Calling: " + " ".join(cmd))
            return self.run_cli(cmd, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            LOG.error("ERR: solana error {}".format(err))
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
            cmd = ["neon-cli",
                   "--commitment=recent",
                   "--url", self._config.solana_url,
                   f"--evm_loader={str(self._config.evm_loader_id)}",
                   f"--loglevel={self._emulator_logging_level}"
                   ]\
                  + (["-vvv"] if self._config.neon_cli_debug_log else [])\
                  + list(args)
            LOG.info("Calling neon-cli: " + " ".join(cmd))

            if data is None:
                data = ""

            result = subprocess.run(cmd, input=data, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True, timeout=self._config.neon_cli_timeout)

            output = json.loads(result.stdout)
            for log in output.get("logs", []):
                LOG.debug(log)

            if "error" in output:
                LOG.error("ERR: neon-cli error value '{}'".format(output["error"]))
                raise subprocess.CalledProcessError(result.returncode, cmd, stderr=output["error"])

            return output.get("value", "")
        except subprocess.CalledProcessError as err:
            LOG.error("ERR: neon-cli error {}".format(err))
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
            LOG.error("ERR: neon-cli error {}".format(err))
            raise
