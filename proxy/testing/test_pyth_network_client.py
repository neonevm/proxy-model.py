import unittest
from proxy.indexer.pythnetwork import PythNetworkClient
from solana.rpc.api import Client as SolanaClient
from solana.publickey import PublicKey
from time import sleep

# Will perform tests with devnet network
# CI Airdropper that is already running in parallel (see docker-compose-test.yml)
# uses mainnet-beta. 
# PythNetworkClient will fail with 'too many requests' if trying to connect
# it to the same Solana network
solana_url = "https://api.devnet.solana.com"
mapping_account = PublicKey('BmA9Z6FjioHJPpjT39QazZyhDRUdZy2ezwx4GiDdE2u2')
sol_usd_symbol = 'Crypto.SOL/USD'

class TestPythNetworkClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.testee = PythNetworkClient(SolanaClient(solana_url))
        cls.update_mapping(cls)

    def update_mapping(self):
        self.testee.update_mapping(mapping_account)

    def test_succes_update_mapping(self):
        try:
            self.update_mapping()
        except Exception as err:
            self.fail(f"Expected update_mapping not throws exception but it does: {err}")

    def test_success_read_price(self):
        try:
            price1 = self.testee.get_price(sol_usd_symbol)
            sleep(15)
            price2 = self.testee.get_price(sol_usd_symbol)
            self.assertTrue(price1['price'] != price2['price'])
        except Exception as err:
            self.fail(f"Expected get_price not throws exception but it does: {err}")