import unittest

from proxy.testing.testing_helpers import Proxy

SEED = 'https://github.com/neonlabsorg/proxy-model.py/issues/210'

TEST_EVENT_SOURCE_210 = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.5.12;

contract ReturnsEvents {
    event Added(uint8 sum);

    function addNoReturn(uint8 x, uint8 y) public {
        x + y;
    }

    function addReturn(uint8 x, uint8 y) public returns(uint8) {
        return x + y;
    }

    function addReturnEvent(uint8 x, uint8 y) public returns(uint8) {
        uint8 sum =x+y;

        emit Added(sum);
        return sum;
    }

    function addReturnEventTwice(uint8 x, uint8 y) public returns(uint8) {
        uint8 sum = x + y;
        emit Added(sum);
        sum += y;
        emit Added(sum);
        return sum;
    }
}
'''


class TestEthGetLogs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\n\n")
        print(SEED)
        cls.proxy = Proxy()
        cls.eth_account = cls.proxy.create_signer_account(SEED)
        print('eth_account.address:', cls.eth_account.address)
        print('eth_account.key:', cls.eth_account.key.hex())

        cls.block_hashes = []
        cls.topics = []
        cls.block_numbers = []

        cls.block_hashes_no_event = []
        cls.block_numbers_no_event = []

        cls.deploy_contract(cls)
        cls.commit_transactions(cls)

        print(cls.block_hashes)
        print(cls.topics)
        print(cls.block_numbers)
        print(cls.block_hashes_no_event)
        print(cls.block_numbers_no_event)

    def deploy_contract(self):
        deployed_info = self.proxy.compile_and_deploy_contract(self.eth_account, TEST_EVENT_SOURCE_210)
        print('trx_deploy_hash:', deployed_info.tx_hash.hex())
        print('trx_deploy_receipt:', deployed_info.tx_receipt)

        self.storage_contract = deployed_info.contract

    def commit_transactions(self):
        self.commit_one_event_trx(1, 2)
        self.commit_one_event_trx(2, 3)
        self.commit_two_event_trx(3, 4)
        self.commit_two_event_trx(5, 6)
        self.commit_no_event_trx(7, 8)
        self.commit_no_event_trx(9, 0)

    def commit_one_event_trx(self, x, y) -> None:
        print(f"\ncommit_one_event_trx. x: {x}, y: {y}")
        tx_store = self.storage_contract.functions.addReturnEvent(x, y).build_transaction()
        tx_store = self.proxy.sign_send_wait_transaction(self.eth_account, tx_store)

        print('trx_store_receipt:', tx_store.tx_receipt)
        self.block_hashes.append(tx_store.tx_receipt['blockHash'].hex())
        self.block_numbers.append(hex(tx_store.tx_receipt['blockNumber']))
        for log in tx_store.tx_receipt['logs']:
            for topic in log['topics']:
                self.topics.append(topic.hex())

    def commit_two_event_trx(self, x, y) -> None:
        print(f"\ncommit_two_event_trx. x: {x}, y: {y}")
        tx_store = self.storage_contract.functions.addReturnEventTwice(x, y).build_transaction()
        tx_store = self.proxy.sign_send_wait_transaction(self.eth_account, tx_store)

        print('trx_store_receipt:', tx_store.tx_receipt)
        self.block_hashes.append(tx_store.tx_receipt['blockHash'].hex())
        self.block_numbers.append(hex(tx_store.tx_receipt['blockNumber']))
        for log in tx_store.tx_receipt['logs']:
            for topic in log['topics']:
                self.topics.append(topic.hex())

    def commit_no_event_trx(self, x, y) -> None:
        print("\ncommit_no_event_trx")
        tx_store = self.storage_contract.functions.addReturn(x, y).build_transaction()
        tx_store = self.proxy.sign_send_wait_transaction(self.eth_account, tx_store)

        print('trx_store_receipt:', tx_store.tx_receipt)
        self.block_hashes_no_event.append(tx_store.tx_receipt['blockHash'].hex())
        self.block_numbers_no_event.append(hex(tx_store.tx_receipt['blockNumber']))

    def test_get_logs_by_blockHash(self):
        print("\ntest_get_logs_by_blockHash")
        receipts = self.proxy.conn.get_logs({
            'blockHash': self.block_hashes[0],
            'address': self.storage_contract.address
        })
        print('receipts: ', receipts)
        self.assertEqual(len(receipts), 1)

    def test_get_no_logs_by_blockHash(self):
        print("\ntest_get_no_logs_by_blockHash")
        receipts = self.proxy.conn.get_logs({
            'blockHash': self.block_hashes_no_event[0],
            'address': self.storage_contract.address
        })
        print('receipts: ', receipts)
        self.assertEqual(len(receipts), 0)

    def test_get_logs_by_fromBlock(self):
        print("\ntest_get_logs_by_fromBlock")
        receipts = self.proxy.conn.get_logs({
            'fromBlock': self.block_numbers[2],
            'address': self.storage_contract.address
        })
        print('receipts: ', receipts)
        self.assertEqual(len(receipts), 4)

    def test_get_logs_complex_request(self):
        print("\ntest_get_logs_complex_request")
        receipts = self.proxy.conn.get_logs({
            'fromBlock': 0,
            'toBlock': 'latest',
            'address': self.storage_contract.address,
            'topics': self.topics
        })
        print('receipts: ', receipts)
        self.assertEqual(len(receipts), 6)

    def test_get_logs_by_address(self):
        print("\ntest_get_logs_by_address")
        receipts = self.proxy.conn.get_logs({'address': self.storage_contract.address})
        print('receipts: ', receipts)
        self.assertEqual(len(receipts), 6)


if __name__ == '__main__':
    unittest.main()
