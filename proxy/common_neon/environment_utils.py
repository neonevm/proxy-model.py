import json
import os
import subprocess
import sys
from typing import List, Optional

import logging
from logged_groups import logged_group, LogMng

from ..common_neon.solana_transaction import SolAccount
from ..common_neon.config import Config


class CliBase:
    def __init__(self, config: Config):
        self._config = config

    def run_cli(self, cmd: List[str], data: str = None, **kwargs) -> bytes:
        self.debug("Calling: " + " ".join(cmd))

        if data:
            proc_result = subprocess.run(cmd, input=data, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         **kwargs)
        else:
            proc_result = subprocess.run(cmd, input="", text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         **kwargs)
        if proc_result.stderr is not None:
            print(proc_result.stderr, file=sys.stderr)
        output = proc_result.stdout
        if not output:
            proc_result.check_returncode()
        return output


@logged_group("neon.Proxy")
class solana_cli(CliBase):
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


@logged_group("neon.Proxy")
def get_solana_accounts(config, *, logger) -> List[SolAccount]:
    def read_sol_account(name) -> Optional[SolAccount]:
        if not os.path.isfile(name):
            return None
        logger.debug(f"Open a sol_account file: {name}")
        with open(name.strip(), mode='r') as d:
            pkey = (d.read())
            num_list = [int(v) for v in pkey.strip("[] \n").split(',')]
            value_list = bytes(num_list[0:32])
            return SolAccount(value_list)

    res = solana_cli(config).call('config', 'get')
    logger.debug(f"Got solana config: {res}")
    substr = "Keypair Path: "
    path = ""
    for line in res.splitlines():
        if line.startswith(substr):
            path = line[len(substr):].strip()
    if path == "":
        raise Exception("cannot get keypair path")

    path = path.strip()

    signer_list = []
    (file_name, file_ext) = os.path.splitext(path)
    i = 0
    while True:
        i += 1
        full_path = file_name + (str(i) if i > 1 else '') + file_ext
        signer = read_sol_account(full_path)
        if not signer:
            break
        signer_list.append(signer)
        logger.debug(f'Add signer: {signer.public_key()}')

    if not len(signer_list):
        raise Exception("No keypairs")
    logger.debug(f"Got signer list of: {len(signer_list)} - keys")
    return signer_list


@logged_group("neon.Proxy")
class neon_cli(CliBase):

    EMULATOR_LOGLEVEL = { logging.CRITICAL: "off", logging.ERROR: "error", logging.WARNING: "warn",
                          logging.INFO: "info", logging.DEBUG: "debug", logging.NOTSET: "warn" }

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
