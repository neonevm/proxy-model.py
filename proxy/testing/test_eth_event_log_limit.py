import unittest

from proxy.testing.testing_helpers import Proxy

SEED = 'https://github.com/neonlabsorg/proxy-model.py/issues/812'

TEST_EVENT_SOURCE_812 = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0;

contract GenerateEvents {
    event Frob(bytes);

    function frobnicate(uint size, bytes1 char) public {
        bytes memory s = new bytes(size);
        for (uint i = 0; i < size; i++) {
            s[i] = char;
        }
        emit Frob(s);
    }
}
'''

class Test_eth_event_log_limit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proxy = Proxy()
        cls.eth_account = cls.proxy.create_signer_account(SEED)
        print("\n\n")
        print(SEED)
        print('eth_account.address:', cls.eth_account.address)
        print('eth_account.key:', cls.eth_account.key.hex())

        cls.block_hashes = []
        cls.block_numbers = []
        cls.topics = []

        cls.deploy_contract(cls)
        cls.commit_transactions(cls)

        print(cls.block_hashes)
        print(cls.block_numbers)
        print(cls.topics)

    @classmethod
    def tearDownClass(cls) -> None:
        pass

    def deploy_contract(self):
        deployed_info = self.proxy.compile_and_deploy_contract(self.eth_account, TEST_EVENT_SOURCE_812)
        self.storage_contract = deployed_info.contract

    def commit_transactions(self):
        self.commit_event_trx(self, 1000, 41)
        self.commit_event_trx(self, 2000, 42)
        self.commit_event_trx(self, 3000, 43)

    def commit_event_trx(self, event_size: int, char: int) -> None:
        print("\ncommit_event_trx(", event_size, char, ")")
        tx_store = self.storage_contract.functions.frobnicate(event_size, bytes([char])).build_transaction()
        tx_store = self.proxy.sign_send_wait_transaction(self.eth_account, tx_store)

        print('trx_store_receipt:', tx_store.tx_receipt)
        self.block_hashes.append(tx_store.tx_receipt['blockHash'].hex())
        self.block_numbers.append(hex(tx_store.tx_receipt['blockNumber']))
        for log in tx_store.tx_receipt['logs']:
            for topic in log['topics']:
                self.topics.append(topic.hex())

    def test_get_logs_by_blockHash(self):
        print("\ntest_get_logs_by_blockHash")
        receipts = self.proxy.conn.get_logs({'blockHash': self.block_hashes[0]})
        print('receipts[0]: ', receipts)
        receipts = self.proxy.conn.get_logs({'blockHash': self.block_hashes[1]})
        print('receipts[1]: ', receipts)
        receipts = self.proxy.conn.get_logs({'blockHash': self.block_hashes[2]})
        print('receipts[2]: ', receipts)
        pass


if __name__ == '__main__':
    unittest.main()
