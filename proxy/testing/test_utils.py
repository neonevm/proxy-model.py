import unittest
from ..common_neon.utils import get_from_dict, cached_method


class TestMethod:
    def __init__(self, value: int):
        self._value = 10

    @cached_method
    def get_value(self) -> int:
        self._value += 1
        return self._value


class TestUtils(unittest.TestCase):

    def test_get_from_dict(self):
        test_dict = {"a": {"b": {"c": 1}}}

        self.assertEqual(1, get_from_dict(test_dict, ("a", "b", "c"), None))
        self.assertEqual({"b": {"c": 1}}, get_from_dict(test_dict, ("a", ), None))

        self.assertIsNone(get_from_dict(test_dict, ("b", "c", "a"), None))
        self.assertIsNone(get_from_dict(None, ("a",), None))
        self.assertIsNone(get_from_dict(555, ("a", ), None))
        self.assertIsNone(get_from_dict({}, ("a", ), None))

    def test_cached_method(self):
        test_m = TestMethod(10)
        for i in range(10):
            self.assertEqual(test_m.get_value(), 11)

        test_m.get_value.reset_cache(test_m)
        for i in range(10):
            self.assertEqual(test_m.get_value(), 12)

