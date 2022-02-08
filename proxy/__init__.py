# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from .proxy import entry_point
from .proxy import main, start
from .proxy import Proxy
from .testing.test_case import TestCase

__all__ = [
    # PyPi package entry_point. See
    # https://github.com/abhinavsingh/proxy.py#from-command-line-when-installed-using-pip
    'entry_point',
    # Embed proxy.py. See
    # https://github.com/abhinavsingh/proxy.py#embed-proxypy
    'main', 'start',
    # Unit testing with proxy.py. See
    # https://github.com/abhinavsingh/proxy.py#unit-testing-with-proxypy
    'TestCase',
    'Proxy',
]
