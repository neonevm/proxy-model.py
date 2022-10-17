import unittest

from proxy.testing.testing_helpers import Proxy

REVERTING_SOLIDITY_SOURCE_487 = '''
pragma solidity >=0.7.0 <0.9.0;
/**
 * @title Counter
 * @dev Counter & inc/dec value in a variable
 */
contract Reverting {
    function do_revert() public returns (uint256) {
        require(2>3, 'revert');
        return 1;
    }

    function consume_a_lot() public returns (uint256) {
        uint256 SOME_BIG_INT = 800000;
        require(gasleft() >= SOME_BIG_INT, "!gas");
        return 1;
    }
}
'''


class Test_eth_estimateGas(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proxy = Proxy()
        cls.eth_account = cls.proxy.create_signer_account('https://github.com/neonlabsorg/proxy-model.py/issues/147')
        print("\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/487")
        print('eth_account.address:', cls.eth_account.address)
        print('eth_account.key:', cls.eth_account.key.hex())
        cls.deploy_counter_487_solidity_contract(cls)

    def deploy_counter_487_solidity_contract(self):
        deployed_info = self.proxy.compile_and_deploy_contract(self.eth_account, REVERTING_SOLIDITY_SOURCE_487)

        self.deploy_block_hash = deployed_info.tx_receipt['blockHash']
        self.deploy_block_num = deployed_info.tx_receipt['blockNumber']
        print('deploy_block_hash:', self.deploy_block_hash)
        print('deploy_block_num:', self.deploy_block_num)

        self.reverting_contract = deployed_info.contract

    # @unittest.skip("a.i.")
    def test_01_check_do_revert(self):
        print("\ntest_01_check_do_revert")
        try:
            trx_revert = self.reverting_contract.functions.do_revert().build_transaction(
                {'from': self.eth_account.address})
            print('trx_revert:', trx_revert)
            trx_estimate_gas_response = self.proxy.conn.estimate_gas(trx_revert)
            print('trx_estimate_gas_response:', trx_estimate_gas_response)
            self.assertTrue(False)
        except Exception as e:
            print('type(e):', type(e))
            print('e:', e)
            self.assertTrue(True)

    # @unittest.skip("a.i.")
    def test_02_check_no_revert_big_gas(self):
        print("\ntest_02_check_no_revert_big_gas")
        trx_big_gas = self.reverting_contract.functions.consume_a_lot().build_transaction(
            {'from': self.eth_account.address})
        print('trx_big_gas:', trx_big_gas)
        trx_estimate_gas_response = self.proxy.conn.estimate_gas(trx_big_gas)
        print('trx_estimate_gas_response:', trx_estimate_gas_response)


if __name__ == '__main__':
    unittest.main()
