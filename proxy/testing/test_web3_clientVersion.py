import unittest
import os
from proxy.testing.testing_helpers import Proxy


neon_revision = os.environ.get('NEON_REVISION', 'env var NEON_REVISION is not set')


class TestWeb3clientVersion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proxy = Proxy()
        cls.eth_account = cls.proxy.create_account('web3_clientVersion')
        print('\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/205')
        print('eth_account.address:', cls.eth_account.address)
        print('eth_account.key:', cls.eth_account.key.hex())

    def test_web3_clientVersion(self):
        print('check tag Neon/v in web3_clientVersion')
        web3_clientVersion = self.proxy.conn.w3.clientVersion
        print('web3_clientVersion:', web3_clientVersion)
        self.assertTrue(web3_clientVersion.startswith('Neon/v'))
        print('check for neon_revision:', neon_revision)
        self.assertTrue(web3_clientVersion.endswith(neon_revision))


if __name__ == '__main__':
    unittest.main()
