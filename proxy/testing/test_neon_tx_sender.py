import os
import unittest

import logged_groups
from typing import List

from ..common_neon.config import Config
from ..common_neon.errors import BadResourceError

from ..common_neon.solana_interactor import SolInteractor

from ..mempool.operator_resource_mng import OpResMng, OpResInit, OpResInfo


class FakeConfig(Config):
    def set_min_operator_balance_to_warn(self, warn_list: List[int]):
        self._warn_list = warn_list

    @property
    def min_operator_balance_to_warn(self) -> int:
        if len(self._warn_list) > 1:
            value = self._warn_list.pop(0)
        else:
            value = self._warn_list[0]
        return value

    def set_min_operator_balance_to_err(self, err_list: List[int]):
        self._err_list = err_list

    @property
    def min_operator_balance_to_err(self) -> int:
        if len(self._err_list) > 1:
            value = self._err_list.pop(0)
        else:
            value = self._err_list[0]
        return value


@logged_groups.logged_group("neon.TestCases")
class TestNeonTxSender(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        config = Config()
        cls.solana = SolInteractor(config, config.solana_url)

    def setUp(self) -> None:
        self._config = FakeConfig()
        self._resource_list = OpResMng(self._config)
        for resource_ident in self._resource_list.get_disabled_resource_list():
            self._resource_list.enable_resource(resource_ident)
        self._resource_ident = self._resource_list.get_resource('test-tx-hash')
        self._resource = OpResInfo.from_ident(self._resource_ident)
        self._resource_initializer = OpResInit(self._config, self.solana)

    # @unittest.skip("a.i.")
    def test_01_validate_execution_when_not_enough_sols(self):
        """
        If the balance value of one of the operator's accounts has become equal to
        the value of the variable MIN_OPERATOR_BALANCE_TO_ERR or less,
        then an error is returned to the client who requested the execution of the transaction
        and an error is written to the log.
        """
        self._config.set_min_operator_balance_to_warn([1_049_000_000 * 1_000_000_000 * 1_000_000_000 * 2, 1_000_000_000 * 2])
        self._config.set_min_operator_balance_to_err([1_049_000_000 * 1_000_000_000 * 1_000_000_000, 1_000_000_000])

        with self.assertLogs('neon.MemPool', level='ERROR') as logs:
            with self.assertRaises(BadResourceError) as context:
                self._resource_initializer.init_resource(self._resource)
            self.assertTrue('Not enough SOLs on the resource' in str(context.exception))
            print('logs.output:', str(logs.output))
            self.assertRegex(str(logs.output), 'ERROR:neon.MemPool:Operator account [A-Za-z0-9]{40,}:[0-9]+ has NOT enough SOLs; balance = [0-9]+; min_operator_balance_to_err = 1049000000000000000000000000')

    # @unittest.skip("a.i.")
    def test_02_validate_warning_when_little_sols(self):
        """
        If the balance value of one of the operator's accounts becomes equal to
        the value of the variable MIN_OPERATOR_BALANCE_TO_WARN or less,
        then a warning is written to the log.:
        """
        self._config.set_min_operator_balance_to_warn([1_049_000_000 * 1_000_000_000 * 1_000_000_000, 1_000_000_000 * 2])
        self._config.set_min_operator_balance_to_err([1_049_049_000, 1_000_000_000])

        with self.assertLogs('neon.MemPool', level='WARNING') as logs:
            self._resource_initializer.init_resource(self._resource)
            print('logs.output:', str(logs.output))
            self.assertRegex(str(logs.output), 'WARNING:neon.MemPool:Operator account [A-Za-z0-9]{40,}:[0-9]+ SOLs are running out; balance = [0-9]+; min_operator_balance_to_warn = 1049000000000000000000000000; min_operator_balance_to_err = 1049049000;')

    # @unittest.skip("a.i.")
    def test_03_validate_execution_when_not_enough_sols_for_all_operator_accounts(self):
        """
        If the balance value of the all operator's accounts has become equal to
        the value of the variable MIN_OPERATOR_BALANCE_TO_ERR or less,
        then an error (RuntimeError('No resources!') )is returned to the client
        who requested the execution of the transaction
        and an error is written to the log.
        """
        self._config.set_min_operator_balance_to_warn([1_049_000_000 * 1_000_000_000 * 1_000_000_000 * 2])
        self._config.set_min_operator_balance_to_err([1_049_000_000 * 1_000_000_000 * 1_000_000_000])

        with self.assertLogs('neon.MemPool', level='ERROR') as logs:
            with self.assertRaises(BadResourceError) as context:
                self._resource_initializer.init_resource(self._resource)
            self.assertTrue('Not enough SOLs on the resource' in str(context.exception))
            print('logs.output:', str(logs.output))
            self.assertRegex(str(logs.output), 'ERROR:neon.MemPool:Operator account [A-Za-z0-9]{40,}:[0-9]+ has NOT enough SOLs; balance = [0-9]+; min_operator_balance_to_err = 1049000000000000000000000000')

