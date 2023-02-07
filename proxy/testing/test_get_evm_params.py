import unittest

from proxy.testing.testing_helpers import Proxy


class TestGetEvmParam(unittest.TestCase):
    def test_all_cases(self):
        proxy = Proxy()
        print(f'Neon-EVM Params: {proxy.web3.neon.getEvmParams()}')

