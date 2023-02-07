# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import os
import inspect
import logging
import importlib
import itertools
from typing import Any, Dict, List, Tuple, Union, Optional

from .utils import text_, bytes_
from .constants import DOT, COMMA, DEFAULT_ABC_PLUGINS


logger = logging.getLogger(__name__)


class Plugins:
    """Common utilities for plugin discovery."""

    @staticmethod
    def resolve_plugin_flag(flag_plugins: Any, opt_plugins: Optional[Any] = None) -> List[Union[bytes, type]]:
        if isinstance(flag_plugins, list):
            requested_plugins = list(
                itertools.chain.from_iterable([
                    p.split(text_(COMMA)) for p in list(
                        itertools.chain.from_iterable(flag_plugins),
                    )
                ]),
            )
        else:
            requested_plugins = flag_plugins.split(text_(COMMA))
        return [
            p if isinstance(p, type) else bytes_(p)
            for p in (opt_plugins if opt_plugins is not None else requested_plugins)
            if not (isinstance(p, str) and len(p) == 0)
        ]

    @staticmethod
    def discover(input_args: List[str]) -> None:
        """Search for external plugin found in command line arguments,
        then iterates over each value and discover/import the plugin.
        """
        for i, f in enumerate(input_args):
            if f in ('--plugin', '--plugins', '--auth-plugin'):
                v = input_args[i + 1]
                parts = v.split(',')
                for part in parts:
                    Plugins.importer(bytes_(part))

    @staticmethod
    def load(
        plugins: List[Union[bytes, type]],
        abc_plugins: Optional[List[str]] = None,
    ) -> Dict[bytes, List[type]]:
        """Accepts a list Python modules, scans them to identify
        if they are an implementation of abstract plugin classes and
        returns a dictionary of matching plugins for each abstract class.
        """
        p: Dict[bytes, List[type]] = {}
        for abc_plugin in (abc_plugins or DEFAULT_ABC_PLUGINS):
            p[bytes_(abc_plugin)] = []
        for plugin_ in plugins:
            klass, module_name = Plugins.importer(plugin_)
            assert klass and module_name
            mro = list(inspect.getmro(klass))
            # Find the base plugin class that
            # this plugin_ is implementing
            base_klass = None
            for k in mro:
                if bytes_(k.__name__) in p:
                    base_klass = k
                    break
            if base_klass is None:
                raise ValueError('%s is NOT a valid plugin' % text_(plugin_))
            if klass not in p[bytes_(base_klass.__name__)]:
                p[bytes_(base_klass.__name__)].append(klass)
            logger.info('Loaded plugin %s.%s', module_name, klass.__name__)
        # print(p)
        return p

    @staticmethod
    def importer(plugin: Union[bytes, type]) -> Tuple[type, str]:
        """Import and returns the plugin."""
        if isinstance(plugin, type):
            return (plugin, '__main__')
        plugin_ = text_(plugin.strip())
        assert plugin_ != ''
        module_name, klass_name = plugin_.rsplit(text_(DOT), 1)
        klass = getattr(
            importlib.import_module(
                module_name.replace(
                    os.path.sep, text_(DOT),
                ),
            ),
            klass_name,
        )
        return (klass, module_name)
