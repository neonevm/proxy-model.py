import unittest

from proxy.common_neon.emulator_interactor import decode_revert_message


class TestContractReverting(unittest.TestCase):

    def test_revert_message_decoding(self):
        revert_message = decode_revert_message(self._STRING_BASED_REVERT_DATA)
        self.assertEqual(revert_message, "Not enough Ether provided.")

    _STRING_BASED_REVERT_DATA = "08c379a0" \
                                "0000000000000000000000000000000000000000000000000000000000000020" \
                                "000000000000000000000000000000000000000000000000000000000000001a" \
                                "4e6f7420656e6f7567682045746865722070726f76696465642e000000000000"
