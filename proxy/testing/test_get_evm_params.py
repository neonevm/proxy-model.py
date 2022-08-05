import os
import unittest
from ..common_neon.web3 import NeonWeb3 as Web3
from ..common_neon.elf_params import ElfParams

proxy_url = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))

class TestGetEvmParam(unittest.TestCase):
    def test_all_cases(self):
        self.assertEqual(proxy.neon.getEvmParams('NEON_ADDITIONAL_FEE'), ElfParams().get_param('NEON_ADDITIONAL_FEE'))
        self.assertEqual(proxy.neon.getEvmParams('NEON_POOL_BASE'), ElfParams().get_param('NEON_POOL_BASE'))
        self.assertEqual(proxy.neon.getEvmParams('NEON_HEAP_FRAME'), ElfParams().get_param('NEON_HEAP_FRAME'))
        self.assertEqual(proxy.neon.getEvmParams('NEON_COMPUTE_UNITS'), ElfParams().get_param('NEON_COMPUTE_UNITS'))
        self.assertRaises(ValueError, proxy.neon.getEvmParams, ('Unknown Parameter!!!'))
