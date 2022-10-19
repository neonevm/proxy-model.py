import unittest
import os

from proxy.common_neon.elf_params import ElfParams
from proxy.common_neon.config import Config
from proxy.testing.testing_helpers import Proxy


class TestEnvironment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._proxy = Proxy()

    def test_read_elf_params(self):
        print("\n\nhttps://github.com/neonlabsorg/neon-evm/issues/347")
        elf_params = ElfParams().read_elf_param_dict_from_net(Config()).elf_param_dict

        neon_chain_id = elf_params.get('NEON_CHAIN_ID', None)
        self.assertTrue(neon_chain_id is not None)
        self.assertEqual(neon_chain_id, os.environ.get('NEON_CHAIN_ID', None))

        neon_token_mint = elf_params.get('NEON_TOKEN_MINT', None)
        self.assertTrue(neon_token_mint is not None)
        self.assertEqual(neon_token_mint, os.environ.get('NEON_TOKEN_MINT', None))

        neon_pool_base = elf_params.get('NEON_POOL_BASE', None)
        self.assertTrue(neon_pool_base is not None)
        self.assertEqual(neon_pool_base, os.environ.get('NEON_POOL_BASE', None))

    def test_neon_chain_id(self):
        print("\n\nhttps://github.com/neonlabsorg/neon-evm/issues/347")
        neon_chain_id = os.environ.get('NEON_CHAIN_ID', None)
        print(f"NEON_CHAIN_ID = {neon_chain_id}")
        self.assertTrue(neon_chain_id is not None)

        eth_chainid: int = self._proxy.conn.chain_id
        print(f"eth_chainId = {eth_chainid}")
        self.assertEqual(eth_chainid, int(neon_chain_id))

        net_version: str = self._proxy.conn.w3.net.version
        print(f"net_version = {net_version}")
        self.assertEqual(net_version, neon_chain_id)
