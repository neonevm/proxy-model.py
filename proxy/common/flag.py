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
import sys
import base64
import socket
import argparse
import ipaddress
import itertools
import collections
import multiprocessing
from typing import Any, List, Optional, cast

from .types import IpAddress
from .utils import bytes_, is_py2, is_threadless, set_open_file_limit
from .logger import Logger
from .plugins import Plugins
from .version import __version__
from .constants import (
    COMMA, IS_WINDOWS,
    PLUGIN_WEB_SERVER, DEFAULT_NUM_WORKERS,
    DEFAULT_NUM_ACCEPTORS,
    DEFAULT_DISABLE_HEADERS, PY2_DEPRECATION_MESSAGE,
    DEFAULT_DATA_DIRECTORY_PATH, DEFAULT_MIN_COMPRESSION_LENGTH,
)


__homepage__ = 'https://github.com/abhinavsingh/proxy.py'


# TODO: Currently `initialize` staticmethod contains knowledge
# about several common flags defined by proxy.py core.

# This logic must be decoupled.  flags.add_argument must
# also provide a callback to resolve the final flag value
# based upon availability in input_args, **opts and
# default values.

# Supporting such a framework is complex but achievable.
# One problem is that resolution of certain flags
# can depend upon availability of other flags.

# This will lead us into dependency graph modeling domain.
class FlagParser:
    """Wrapper around argparse module.

    Import `flag.flags` and use `add_argument` API
    to define custom flags within respective Python files.

    Best Practice::

       1. Define flags at the top of your class files.
       2. DO NOT add flags within your class `__init__` method OR
          within class methods.  It MAY result into runtime exception,
          especially if your class is initialized multiple times or if
          class method registering the flag gets invoked multiple times.

    """

    def __init__(self) -> None:
        self.args: Optional[argparse.Namespace] = None
        self.actions: List[str] = []
        self.parser = argparse.ArgumentParser(
            description='proxy.py v%s' % __version__,
            epilog='Proxy.py not working? Report at: %s/issues/new' % __homepage__,
        )

    def add_argument(self, *args: Any, **kwargs: Any) -> argparse.Action:
        """Register a flag."""
        action = self.parser.add_argument(*args, **kwargs)
        self.actions.append(action.dest)
        return action

    def parse_args(
            self, input_args: Optional[List[str]],
    ) -> argparse.Namespace:
        """Parse flags from input arguments."""
        self.args = self.parser.parse_args(input_args)
        return self.args

    @staticmethod
    def initialize(
        input_args: Optional[List[str]] = None,
        **opts: Any,
    ) -> argparse.Namespace:
        if input_args is None:
            input_args = []

        if is_py2():
            print(PY2_DEPRECATION_MESSAGE)
            sys.exit(1)

        # Discover flags from requested plugin.
        # This will also surface external plugin flags
        # under --help.
        Plugins.discover(input_args)

        # Parse flags
        args = flags.parse_args(input_args)

        # Print version and exit
        if args.version:
            print(__version__)
            sys.exit(0)

        # proxy.py currently cannot serve over HTTPS and also perform TLS interception
        # at the same time.  Check if user is trying to enable both feature
        # at the same time.
        #
        # TODO: Use parser.add_mutually_exclusive_group()
        # and remove this logic from here.
        if (args.cert_file and args.key_file) and \
                (args.ca_key_file and args.ca_cert_file and args.ca_signing_key_file):
            print(
                'You can either enable end-to-end encryption OR TLS interception,'
                'not both together.',
            )
            sys.exit(1)

        # Setup logging module
        Logger.setup(args.log_file, args.log_level, args.log_format)

        # Setup limits
        set_open_file_limit(args.open_file_limit)

        # Load work_klass
        work_klass = opts.get('work_klass', args.work_klass)
        work_klass = Plugins.importer(bytes_(work_klass))[0] \
            if isinstance(work_klass, str) \
            else work_klass

        # --enable flags must be parsed before loading plugins
        # otherwise we will miss the plugins passed via constructor
        args.enable_web_server = cast(
            bool,
            opts.get(
                'enable_web_server',
                args.enable_web_server,
            ),
        )

        # Load default plugins along with user provided --plugins
        default_plugins = [
            bytes_(p)
            for p in FlagParser.get_default_plugins(args)
        ]
        requested_plugins = Plugins.resolve_plugin_flag(
            args.plugins, opts.get('plugins'),
        )
        plugins = Plugins.load(
            default_plugins + requested_plugins,
        )

        # https://github.com/python/mypy/issues/5865
        #
        # def option(t: object, key: str, default: Any) -> Any:
        #     return cast(t, opts.get(key, default))
        args.work_klass = work_klass
        args.plugins = plugins
        args.server_recvbuf_size = cast(
            int,
            opts.get(
                'server_recvbuf_size',
                args.server_recvbuf_size,
            ),
        )
        args.client_recvbuf_size = cast(
            int,
            opts.get(
                'client_recvbuf_size',
                args.client_recvbuf_size,
            ),
        )
        disabled_headers = cast(
            Optional[List[bytes]], opts.get(
                'disable_headers', [
                    header.lower()
                    for header in bytes_(getattr(args, 'disable_headers', b'')).split(COMMA)
                    if header.strip() != b''
                ],
            ),
        )
        args.disable_headers = disabled_headers if disabled_headers is not None else DEFAULT_DISABLE_HEADERS

        args.certfile = cast(
            Optional[str], opts.get(
                'cert_file', args.cert_file,
            ),
        )
        args.keyfile = cast(Optional[str], opts.get('key_file', args.key_file))

        args.ca_key_file = cast(
            Optional[str], opts.get(
                'ca_key_file', getattr(args, 'ca_key_file', None)
            ),
        )
        args.ca_cert_file = cast(
            Optional[str], opts.get(
                'ca_cert_file', getattr(args, 'ca_cert_file', None),
            ),
        )
        args.ca_signing_key_file = cast(
            Optional[str],
            opts.get(
                'ca_signing_key_file',
                getattr(args, 'ca_signing_key_file', None)
            ),
        )
        args.ca_file = cast(
            Optional[str],
            opts.get(
                'ca_file',
                getattr(args, 'ca_file', None)
            ),
        )
        args.openssl = cast(
            Optional[str],
            opts.get(
                'openssl',
                getattr(args, 'openssl', None)
            ),
        )

        args.hostname = cast(
            IpAddress,
            opts.get('hostname', ipaddress.ip_address(args.hostname)),
        )
        args.unix_socket_path = opts.get(
            'unix_socket_path', getattr(args, 'unix_socket_path', None),
        )
        # AF_UNIX is not available on Windows
        # See https://bugs.python.org/issue33408
        if not IS_WINDOWS:
            args.family = socket.AF_UNIX if args.unix_socket_path else (
                socket.AF_INET6 if args.hostname.version == 6 else socket.AF_INET
            )
        else:
            # FIXME: Not true for tests, as this value will be a mock.
            #
            # It's a problem only on Windows.  Instead of a proper
            # fix in the tests, simply commenting this line of assertion
            # for now.
            #
            # assert args.unix_socket_path is None
            args.family = socket.AF_INET6 if args.hostname.version == 6 else socket.AF_INET
        args.port = cast(int, opts.get('port', args.port))
        ports: List[List[int]] = opts.get('ports', args.ports)
        args.ports = [
            int(port) for port in list(
                itertools.chain.from_iterable([] if ports is None else ports),
            )
        ]
        args.backlog = cast(int, opts.get('backlog', args.backlog))
        num_workers = opts.get('num_workers', args.num_workers)
        args.num_workers = cast(
            int, num_workers if num_workers > 0 else multiprocessing.cpu_count(),
        )
        num_acceptors = opts.get('num_acceptors', args.num_acceptors)
        # See https://github.com/abhinavsingh/proxy.py/pull/714 description
        # to understand rationale behind the following logic.
        #
        # Num workers flag or option was found. We will use
        # the same value for num_acceptors when num acceptors flag
        # is absent.
        if num_workers != DEFAULT_NUM_WORKERS and num_acceptors == DEFAULT_NUM_ACCEPTORS:
            args.num_acceptors = args.num_workers
        else:
            args.num_acceptors = cast(
                int, num_acceptors if num_acceptors > 0 else multiprocessing.cpu_count(),
            )

        args.static_server_dir = cast(
            str,
            opts.get(
                'static_server_dir',
                args.static_server_dir,
            ),
        )
        args.min_compression_length = cast(
            bool,
            opts.get(
                'min_compression_length',
                getattr(
                    args, 'min_compression_length',
                    DEFAULT_MIN_COMPRESSION_LENGTH,
                ),
            ),
        )
        args.timeout = cast(int, opts.get('timeout', args.timeout))
        args.local_executor = cast(
            int,
            opts.get(
                'local_executor',
                args.local_executor,
            ),
        )
        args.threaded = cast(bool, opts.get('threaded', args.threaded))
        # Pre-evaluate threadless values based upon environment and config
        #
        # --threadless is now default mode of execution
        # but we still have exceptions based upon OS config.
        # Make sure executors are not started if is_threadless
        # evaluates to False.
        args.threadless = cast(bool, opts.get('threadless', args.threadless))
        args.threadless = is_threadless(args.threadless, args.threaded)

        args.pid_file = cast(
            Optional[str], opts.get(
                'pid_file',
                args.pid_file,
            ),
        )

        args.port_file = cast(
            Optional[str], opts.get(
                'port_file',
                args.port_file,
            ),
        )

        args.proxy_py_data_dir = DEFAULT_DATA_DIRECTORY_PATH
        os.makedirs(args.proxy_py_data_dir, exist_ok=True)

        ca_cert_dir = opts.get('ca_cert_dir', getattr(args, 'ca_cert_dir', None))
        args.ca_cert_dir = cast(Optional[str], ca_cert_dir)
        if args.ca_cert_dir is None:
            args.ca_cert_dir = os.path.join(
                args.proxy_py_data_dir, 'certificates',
            )
        os.makedirs(args.ca_cert_dir, exist_ok=True)

        # FIXME: Necessary here until flags framework provides a way
        # for flag owners to initialize
        args.cache_dir = getattr(args, 'cache_dir', 'cache')
        os.makedirs(args.cache_dir, exist_ok=True)
        os.makedirs(os.path.join(args.cache_dir, 'responses'), exist_ok=True)
        os.makedirs(os.path.join(args.cache_dir, 'content'), exist_ok=True)

        return args

    @staticmethod
    def get_default_plugins(
            args: argparse.Namespace,
    ) -> List[str]:
        """Prepare list of plugins to load based upon
        --enable-* and --disable-* flags.
        """
        default_plugins: List[str] = []
        if args.enable_web_server:
            default_plugins.append(PLUGIN_WEB_SERVER)
        return list(collections.OrderedDict.fromkeys(default_plugins).keys())


flags = FlagParser()
