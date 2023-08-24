# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""


from .neon_proxy_app import NeonProxyApp


if __name__ == '__main__':
    neon_proxy_app = NeonProxyApp()
    neon_proxy_app.start()
