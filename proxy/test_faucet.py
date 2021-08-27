import unittest

class Test_Faucet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n\nTest Faucet Started")

    def test_env(self):
        print("\n# test_env")

    def test_config(self):
        print("\n# test_config")

    @classmethod
    def tearDownClass(cls):
        print("\nTest Faucet Finished")

if __name__ == '__main__':
    unittest.main()
