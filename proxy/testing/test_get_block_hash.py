from typing import List
import unittest

from proxy.testing.testing_helpers import Proxy, TransactionSended, HexBytes


BLOCK_HASH_SOLIDITY_SOURCE = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.5.12;

contract BlockHashTest {
    event Added(bytes32 hash);

    function getCurrentValues() public payable returns (bytes32) {
        uint blockNumber = block.number;
        bytes32 blockHashNow = blockhash(blockNumber);
        emit Added(blockHashNow);
        return blockHashNow;
    }

    function getValues(uint number) public payable returns (bytes32) {
        bytes32 blockHash = blockhash(number);
        emit Added(blockHash);
        return blockHash;
    }
}
'''


class Test_get_block_hash(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proxy = Proxy()
        cls.eth_account = cls.proxy.create_signer_account()
        print("\nTest_get_block_hash\n")
        print('eth_account.address:', cls.eth_account.address)
        print('eth_account.key:', cls.eth_account.key.hex())

        cls.deploy_contract(cls)

    def deploy_contract(self):
        deployed_info = self.proxy.compile_and_deploy_contract(self.eth_account, BLOCK_HASH_SOLIDITY_SOURCE)
        print('tx_deploy_hash:', deployed_info.tx_hash.hex())
        print('tx_deploy_receipt:', deployed_info.tx_receipt)

        self.storage_contract = deployed_info.contract

    def commit_getCurrentValues(self) -> List[str]:
        print("getCurrentValues()")
        tx = self.storage_contract.functions.getCurrentValues().build_transaction({'from': self.eth_account.address})
        tx = self.proxy.sign_send_wait_transaction(self.eth_account, tx)
        return self.sent_tx_get_log(tx)

    def commit_getValues(self, block_num: int) -> List[str]:
        print(f"getValues({block_num})")
        tx = self.storage_contract.functions.getValues(block_num).build_transaction({'from': self.eth_account.address})
        tx = self.proxy.sign_send_wait_transaction(self.eth_account, tx)
        return self.sent_tx_get_log(tx)

    @staticmethod
    def sent_tx_get_log(tx: TransactionSended) -> List[str]:
        topics = []
        print('tx_receipt:', tx.tx_receipt)
        for log in tx.tx_receipt['logs']:
            topics.append(log['data'])
        return topics

    def test_getCurrentBlockHash(self):
        print("\ntest_getCurrentBlockHash")
        logs = self.commit_getCurrentValues()
        self.assertEqual(logs[0], HexBytes('0x0000000000000000000000000000000000000000000000000000000000000000'))

    def test_getBlockHashFromHistory(self):
        print("\ntest_getBlockHashFromHistory")
        current_block_number = self.proxy.conn.block_number
        print(current_block_number)
        block_number_history = max(int(str(current_block_number), 0) - 25, 1)
        block_hash_history = self.proxy.conn.get_block(block_number_history).hash
        logs = self.commit_getValues(block_number_history)
        print(block_hash_history)
        print(logs)
        self.assertEqual(logs[0], block_hash_history)


if __name__ == '__main__':
    unittest.main()
