import unittest

from proxy.testing.testing_helpers import Proxy


class TestEthGetBlockByNumber(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proxy = Proxy()
        cls.eth_account = cls.proxy.create_signer_account('https://github.com/neonlabsorg/proxy-model.py/issues/140')
        print("\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/140")
        print('eth_account.address:', cls.eth_account.address)
        print('eth_account.key:', cls.eth_account.key.hex())

    def test_block_number_with_tag_latest(self):
        print("check tag latest in eth_getBlockByNumber")
        self.proxy.conn.default_block = 'latest'
        try:
            print('proxy.eth.block_number:', self.proxy.conn.block_number)
        except Exception as e:
            print('type(e):', type(e))
            print('Exception:', e)
            self.assertTrue(False)

    def test_block_number_with_tag_earliest(self):
        print("check tag earliest in eth_getBlockByNumber")
        self.proxy.conn.default_block = 'earliest'
        self.assertRaises(Exception, self.proxy.conn.block_number)

    def test_block_number_with_tag_pending(self):
        print("check tag pending in eth_getBlockByNumber")
        self.proxy.conn.default_block = 'pending'
        self.assertRaises(Exception, self.proxy.conn.block_number)


if __name__ == '__main__':
    unittest.main()
