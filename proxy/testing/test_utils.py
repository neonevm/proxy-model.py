import unittest

from ..common_neon.utils import get_from_dict, cached_method, cached_property, u256big_to_hex

from .test_log_bloom import test_tx_log_bloom, test_tx_res_info


class TestCachedMethod:
    def __init__(self, value: int):
        self._value = 10

    @cached_method
    def get_value(self) -> int:
        self._value += 1
        return self._value

    @cached_property
    def value(self) -> int:
        self._value += 1
        return self._value


class TestUtils(unittest.TestCase):

    def test_get_from_dict(self):
        test_dict = {"a": {"b": {"c": 1}}}

        self.assertEqual(1, get_from_dict(test_dict, ("a", "b", "c"), None))
        self.assertEqual({"b": {"c": 1}}, get_from_dict(test_dict, ("a", ), None))

        test_dict_list = {"a": {"b": [10, 20]}}
        self.assertEqual(get_from_dict(test_dict_list, ('a', 'b', 0), -1), 10)
        self.assertEqual(get_from_dict(test_dict_list, ('a', 'b', 2), -1), -1)
        self.assertEqual(get_from_dict(test_dict_list, ('a', 'b', -1), -1), -1)

        self.assertIsNone(get_from_dict(test_dict, ("b", "c", "a"), None))
        self.assertIsNone(get_from_dict(None, ("a",), None))
        self.assertIsNone(get_from_dict(555, ("a", ), None))
        self.assertIsNone(get_from_dict({}, ("a", ), None))

    def test_cached_method(self):
        test_m = TestCachedMethod(10)
        for i in range(10):
            self.assertEqual(test_m.get_value(), 11)

        test_m.get_value.reset_cache(test_m)
        for i in range(10):
            self.assertEqual(test_m.get_value(), 12)

    def test_cached_property(self):
        test_m = TestCachedMethod(10)
        for i in range(10):
            self.assertEqual(test_m.value, 11)

        test_m.__dict__.pop('value', None)
        for i in range(10):
            self.assertEqual(test_m.value, 12)

    def test_log_bloom(self):
        self.assertEqual(
            test_tx_res_info.log_bloom,
            int(test_tx_log_bloom[2:], 16)
        )
        self.assertEqual(
            u256big_to_hex(test_tx_res_info.log_bloom),
            test_tx_log_bloom
        )
