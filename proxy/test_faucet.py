import unittest

class Test_Faucet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n\nTest Faucet Started")

    @classmethod
    def tearDownClass(cls):
        print("\nTest Faucet Finished")

    def test_env(self):
        print("# test_env")

if __name__ == '__main__':
    unittest.main()
