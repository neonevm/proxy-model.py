import unittest

from web3 import exceptions as web3_exceptions
from solana.rpc.api import Client as SolanaClient

from proxy.testing.testing_helpers import Proxy
from proxy.common_neon.emulator_interactor import decode_revert_message
from proxy.common_neon.config import Config


class TestContractReverting(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._proxy = Proxy()

        solana_url = Config().solana_url
        cls._solana_client = SolanaClient(solana_url)

    def test_revert_message_decoding(self):
        revert_message = decode_revert_message(self._STRING_BASED_REVERT_DATA)
        self.assertEqual(revert_message, "Not enough Ether provided.")

    _STRING_BASED_REVERT_DATA = "08c379a0" \
                                "0000000000000000000000000000000000000000000000000000000000000020" \
                                "000000000000000000000000000000000000000000000000000000000000001a" \
                                "4e6f7420656e6f7567682045746865722070726f76696465642e000000000000"

    def test_constructor_raises_string_based_error(self):
        compiled_info = self._proxy.compile_contract(self._CONTRACT_CONSTRUCTOR_STRING_BASED_REVERT)
        with self.assertRaises(web3_exceptions.ContractLogicError) as cm:
            compiled_info.contract.constructor([]).build_transaction()
        self.assertEqual("execution reverted: ListConstructable: empty list", str(cm.exception))

    _CONTRACT_CONSTRUCTOR_STRING_BASED_REVERT = '''
        pragma solidity >=0.7.0 <0.9.0;
        contract ArrConstructable {
            constructor(uint256[] memory vector_) payable {
                require(vector_.length > 0, "ListConstructable: empty list");
            }
        }
    '''

    def test_constructor_raises_no_argument_error(self):
        compiled_info = self._proxy.compile_contract(self._CONTRACT_CONSTRUCTOR_REVERT)
        with self.assertRaises(web3_exceptions.ContractLogicError) as cm:
            compiled_info.contract.constructor([]).build_transaction()
        self.assertEqual("execution reverted", str(cm.exception))

    _CONTRACT_CONSTRUCTOR_REVERT = '''
        pragma solidity >=0.7.0 <0.9.0;
        contract ArrConstructable {
            constructor(uint256[] memory vector_) payable {
                require(vector_.length > 0);
            }
        }
    '''

    def test_method_raises_string_based_error(self):
        contract_owner = self._proxy.create_signer_account()
        contract_info = self._proxy.compile_and_deploy_contract(
            contract_owner, self._CONTRACT_METHOD_STRING_BASED_REVERT
        )
        with self.assertRaises(web3_exceptions.ContractLogicError) as cm:
            contract_info.contract.functions.do_string_based_revert().call()
        self.assertEqual("execution reverted: Predefined revert happened", str(cm.exception))

    def test_method_raises_trivial_error(self):
        contract_owner = self._proxy.create_signer_account()
        contract_info = self._proxy.compile_and_deploy_contract(
            contract_owner, self._CONTRACT_METHOD_STRING_BASED_REVERT
        )
        with self.assertRaises(web3_exceptions.ContractLogicError) as cm:
            contract_info.contract.functions.do_trivial_revert().call()
        self.assertEqual("execution reverted", str(cm.exception))

    _CONTRACT_METHOD_STRING_BASED_REVERT = '''
        pragma solidity >=0.7.0 <0.9.0;
        contract ArrConstructable {
            function do_string_based_revert() public view returns (uint256) {
                require(false, "Predefined revert happened");
            }
            function do_trivial_revert() public view returns (uint256) {
                require(false);
            }
        }
    '''
