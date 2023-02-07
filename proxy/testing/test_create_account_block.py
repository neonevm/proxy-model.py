import unittest

import rlp
from proxy.testing.testing_helpers import Proxy


STORAGE_SOLIDITY_SOURCE = '''
pragma solidity >=0.7.0 <0.9.0;

contract Storage {
    uint256 number;
    /**
     * @dev Store value in variable
     * @param num value to store
     */
    function store(uint256 num) public {
        number = num;
    }
    /**
     * @dev Return value
     * @return value of 'number'
     */
    function retrieve() public view returns (uint256){
        return number;
    }
}
'''


class TestCreateAccountBlock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/147")
        cls.proxy = Proxy()
        cls.eth_account = cls.proxy.create_signer_account()

        print('eth_account.address:', cls.eth_account.address)
        print('eth_account.key:', cls.eth_account.key.hex())
        print('balance:', cls.proxy.conn.get_balance(cls.eth_account.address))

        # Create caller account in NeonEVM
        cls.deploy_contract(cls)

    def deploy_contract(self):
        deployed_info = self.proxy.compile_and_deploy_contract(self.eth_account, STORAGE_SOLIDITY_SOURCE)
        return deployed_info.tx_receipt

    def transfer(self, target_account, value):
        tx = self.proxy.sign_send_wait_transaction(
            self.eth_account,
            dict(
                to=bytes(target_account),
                value=value
            )
        )
        return tx.tx_receipt

    def test_blockAccount(self):
        nonce = self.proxy.conn.get_transaction_count(self.eth_account.address)
        expected_contract_address = self.proxy.web3.keccak(
            rlp.encode((bytes.fromhex(self.eth_account.address[2:]), nonce + 1))
        )[-20:]

        # Create expected contract account
        transfer_receipt = self.transfer(expected_contract_address, 1_000_000_000)
        self.assertEqual(transfer_receipt["status"], 1)

        # Try to deploy to expected contract account
        deploy_receipt = self.deploy_contract()
        self.assertEqual(deploy_receipt["status"], 1)


if __name__ == '__main__':
    unittest.main()
