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
import time
import pathlib
import ipaddress

from typing import List

from .version import __version__

PROXY_PY_START_TIME = time.time()

# /path/to/proxy.py/proxy folder
PROXY_PY_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

CRLF = b'\r\n'
COLON = b':'
WHITESPACE = b' '
COMMA = b','
DOT = b'.'
SLASH = b'/'
HTTP_1_1 = b'HTTP/1.1'

PROXY_AGENT_HEADER_KEY = b'Proxy-agent'
PROXY_AGENT_HEADER_VALUE = b'proxy.py v' + \
    __version__.encode('utf-8', 'strict')
PROXY_AGENT_HEADER = PROXY_AGENT_HEADER_KEY + \
    COLON + WHITESPACE + PROXY_AGENT_HEADER_VALUE

# Defaults
DEFAULT_BACKLOG = 100
DEFAULT_BASIC_AUTH = None
DEFAULT_BUFFER_SIZE = 1024 * 1024
DEFAULT_CA_CERT_DIR = None
DEFAULT_CA_CERT_FILE = None
DEFAULT_CA_KEY_FILE = None
DEFAULT_CA_SIGNING_KEY_FILE = None
DEFAULT_CERT_FILE = None
DEFAULT_CA_FILE = None
DEFAULT_CLIENT_RECVBUF_SIZE = DEFAULT_BUFFER_SIZE
DEFAULT_DEVTOOLS_WS_PATH = b'/devtools'
DEFAULT_DISABLE_HEADERS: List[bytes] = []
DEFAULT_DISABLE_HTTP_PROXY = False
DEFAULT_ENABLE_EVENTS = False
DEFAULT_EVENTS_QUEUE = None
DEFAULT_ENABLE_STATIC_SERVER = False
DEFAULT_ENABLE_WEB_SERVER = False
DEFAULT_IPV4_HOSTNAME = ipaddress.IPv4Address('127.0.0.1')
DEFAULT_IPV6_HOSTNAME = ipaddress.IPv6Address('::1')
DEFAULT_KEY_FILE = None
DEFAULT_LOG_FILE = None
DEFAULT_LOG_FORMAT = '%(asctime)s - pid:%(process)d [%(levelname)-.1s] %(funcName)s:%(lineno)d - %(message)s'
DEFAULT_LOG_LEVEL = 'INFO'
DEFAULT_NUM_WORKERS = 0
DEFAULT_OPEN_FILE_LIMIT = 1024
DEFAULT_PAC_FILE = None
DEFAULT_PAC_FILE_URL_PATH = b'/'
DEFAULT_PID_FILE = None
DEFAULT_PLUGINS = ''
DEFAULT_PORT = 8899
DEFAULT_SERVER_RECVBUF_SIZE = DEFAULT_BUFFER_SIZE
DEFAULT_STATIC_SERVER_DIR = os.path.join(PROXY_PY_DIR, "public")
DEFAULT_THREADLESS = False
DEFAULT_TIMEOUT = 10
DEFAULT_VERSION = False
DEFAULT_HTTP_PORT = 80
DEFAULT_MAX_SEND_SIZE = 16 * 1024

DEFAULT_DATA_DIRECTORY_PATH = os.path.join(str(pathlib.Path.home()), '.proxy')

# Cor plugins enabled by default or via flags
PLUGIN_HTTP_PROXY = 'proxy.http.proxy.HttpProxyPlugin'
PLUGIN_WEB_SERVER = 'proxy.http.server.HttpWebServerPlugin'
