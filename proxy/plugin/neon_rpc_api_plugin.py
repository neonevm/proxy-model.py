# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from __future__ import annotations

import json
import threading
import time
import urllib
from typing import List, Tuple, Dict, Any, Optional

from logged_groups import logged_group, logging_context
from neon_py.utils import gen_unique_id

from ..common.utils import build_http_response
from ..common_neon.errors import EthereumError
from ..common_neon.solana_tx_error_parser import SolTxError
from ..common_neon.config import Config

from ..http.codes import httpStatusCodes
from ..http.parser import HttpParser
from ..http.server import HttpWebServerBasePlugin, httpProtocolTypes
from ..http.websocket import WebsocketFrame

from ..neon_rpc_api_model import NeonRpcApiWorker
from ..statistic import ProxyStatClient, NeonMethodData

modelInstanceLock = threading.Lock()
configInstance: Optional[Config] = None
statInstance: Optional[ProxyStatClient] = None
modelInstance: Optional[NeonRpcApiWorker] = None


@logged_group("neon.Proxy")
class NeonRpcApiPlugin(HttpWebServerBasePlugin):
    """Extend in-built Web Server to add Reverse Proxy capabilities.
    """
    SOLANA_PROXY_LOCATION: str = r'/solana$'

    def __init__(self, *args):
        HttpWebServerBasePlugin.__init__(self, *args)
        self._config, self._stat_client, self._model = NeonRpcApiPlugin.getModel()

    @classmethod
    def getModel(cls) -> Tuple[Config, ProxyStatClient, NeonRpcApiWorker]:
        global modelInstanceLock
        global configInstance
        global statInstance
        global modelInstance

        with modelInstanceLock:
            if modelInstance is None:
                configInstance = Config()
                statInstance = ProxyStatClient(configInstance)
                statInstance.start()
                modelInstance = NeonRpcApiWorker(configInstance)
            return configInstance, statInstance, modelInstance

    def routes(self) -> List[Tuple[int, str]]:
        return [
            (httpProtocolTypes.HTTP, NeonRpcApiPlugin.SOLANA_PROXY_LOCATION),
            (httpProtocolTypes.HTTPS, NeonRpcApiPlugin.SOLANA_PROXY_LOCATION)
        ]

    @staticmethod
    def _sanitize_value(value: Any) -> Any:
        if isinstance(value, str) or isinstance(value, bytes):
            value = urllib.parse.quote_plus(value)
        return value

    def _get_request_value(self, request: Dict[str, Any], name: str) -> Any:
        rpc_value = request.get(name, None)
        return self._sanitize_value(rpc_value)

    def _process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        response = {
            'jsonrpc': '2.0',
            'id': self._get_request_value(request, 'id')
        }

        start_time = time.time()
        rpc_method: Optional[str] = None

        try:
            rpc_method = self._get_request_value(request, 'method')
            if (not hasattr(self._model, rpc_method)) or (not self._model.is_allowed_api(rpc_method)):
                response['error'] = {'code': -32601, 'message': f'method {rpc_method} is not supported'}
            else:
                method = getattr(self._model, rpc_method)
                param_list = [self._sanitize_value(param) for param in request.get('params', [])]
                response['result'] = method(*param_list)
        except SolTxError as err:
            # traceback.print_exc()
            response['error'] = {'code': -32000, 'message': err.error}
        except EthereumError as err:
            # traceback.print_exc()
            response['error'] = err.get_error()
        except BaseException as exc:
            self.debug('Exception on process request', exc_info=exc)
            response['error'] = {'code': -32000, 'message': str(exc)}

        resp_time_ms = (time.time() - start_time) * 1000  # convert this into milliseconds

        self.info(
            'handle_request >>> %s 0x%0x %s %s resp_time_ms= %s',
            threading.get_ident(),
            id(self._model),
            json.dumps(response),
            rpc_method,
            resp_time_ms
        )

        is_error_resp = 'error' in response
        stat = NeonMethodData(name=rpc_method, is_error=is_error_resp, latency=resp_time_ms)
        self._stat_client.commit_request_and_timeout(stat)

        return response

    def handle_request(self, request: HttpParser) -> None:
        req_id = gen_unique_id()
        with logging_context(req_id=req_id):
            self._handle_request_impl(request)
            self.info("Request processed")

    def _handle_request_impl(self, request: HttpParser) -> None:
        if request.method == b'OPTIONS':
            self.client.queue(memoryview(build_http_response(
                httpStatusCodes.OK, reason=b'OK', body=None,
                headers={
                    b'Access-Control-Allow-Origin': b'*',
                    b'Access-Control-Allow-Methods': b'POST, GET, OPTIONS',
                    b'Access-Control-Allow-Headers': b'Content-Type',
                    b'Access-Control-Max-Age': b'86400'
                })))
            return

        try:
            self.info(
                'handle_request <<< %s 0x%x %s', threading.get_ident(), id(self._model),
                request.body.decode('utf8')
            )
            request = json.loads(request.body)
            if isinstance(request, list):
                response = []
                if len(request) == 0:
                    raise Exception("Empty batch request")
                for r in request:
                    response.append(self._process_request(r))
            elif isinstance(request, dict):
                response = self._process_request(request)
            else:
                raise Exception("Invalid request")
        except Exception as err:
            response = {'jsonrpc': '2.0', 'error': {'code': -32000, 'message': str(err)}}

        self.client.queue(memoryview(build_http_response(
            httpStatusCodes.OK, reason=b'OK', body=json.dumps(response).encode('utf8'),
            headers={
                b'Content-Type': b'application/json',
                b'Access-Control-Allow-Origin': b'*',
            })))

    def on_websocket_open(self) -> None:
        pass

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        pass

    def on_websocket_close(self) -> None:
        pass
