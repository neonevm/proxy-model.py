import os
import logging

from ..common_neon.config import Config

from .airdropper import Airdropper


LOG = logging.getLogger(__name__)


class AirdropperApp:

    def __init__(self):
        LOG.info("Airdropper application is starting ...")
        config = Config()
        faucet_url = os.environ['FAUCET_URL']
        wrapper_whitelist = os.environ['INDEXER_ERC20_WRAPPER_WHITELIST']
        if wrapper_whitelist != 'ANY':
            wrapper_whitelist = wrapper_whitelist.split(',')

        max_conf = float(os.environ.get('MAX_CONFIDENCE_INTERVAL', 0.02))

        LOG.info(f"""Construct Airdropper with params: {str(config)}
                  faucet_url: {faucet_url},
                  wrapper_whitelist: {wrapper_whitelist},
                  Max confidence interval: {max_conf}""")

        self._airdropper = Airdropper(config, faucet_url, wrapper_whitelist, max_conf)

    def run(self) -> int:
        try:
            self._airdropper.run()
        except BaseException as exc:
            LOG.error('Failed to start Airdropper', exc_info=exc)
            return 1
        return 0
