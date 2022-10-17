import unittest

from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed

from proxy.common_neon.config import Config
from proxy.testing.solana_utils import WalletAccount, wallet_path
from proxy.testing.testing_helpers import Proxy


CONTRACT = '''
pragma solidity >=0.5.12;
contract Increase_storage {
    mapping(address => mapping(uint256 => uint256)) data;
    uint256 count = 0;
    constructor(){
        inc();
    }
    function inc() public {
        uint256 n = count +  32;
        while (count < n){
            data[msg.sender][count] = uint256(count);
            count = count + 1;
        }
    }
}
'''


class TransactonCost(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.proxy = Proxy()
        print("\n\nhttps://app.zenhub.com/workspaces/solana-evm-6007c75a9dc141001100ccb8/issues/neonlabsorg/proxy-model.py/245")
        self.account = self.proxy.create_signer_account()
        print('account.address:', self.account.address)

        self.client = Client(Config().solana_url)
        wallet = WalletAccount(wallet_path())
        self.acc = wallet.get_acc()

    # @unittest.skip("only for debug")
    def test_deploy_cost(self):
        print("\n\ntest_deploy_cost")

        balance_pre = int(self.client.get_balance(self.acc.public_key, commitment=Confirmed).value)
        print("incoming balance  {:,}".format(balance_pre).replace(',', ' '))

        contract = self.proxy.compile_and_deploy_contract(self.account, CONTRACT)
        print("trx_hash", contract.tx_hash.hex())

        balance_post = int(self.client.get_balance(self.acc.public_key, commitment=Confirmed).value)
        print("outgoing  balance {:,}".format(balance_post).replace(',', ' '))
        print("cost {:,}".format(balance_pre-balance_post).replace(',', ' '))
