import requests

from flask import Flask, jsonify
from threading import Thread
from uuid import uuid4

class MockServer(Thread):
    def request_eth_token_callback(self):
        pass

    def __init__(self, port=3333):
        super().__init__()
        self.port = port
        self.app = Flask(__name__)
        self.url = "http://localhost:%s" % self.port

    def add_callback_response(self, url, callback, methods=('GET',)):
        self.app.add_url_rule(url, view_func=callback, methods=methods)

    def add_json_response(self, url, serializable, methods=('GET',)):
        def callback():
            return jsonify(serializable)

        self.add_callback_response(url, callback, methods=methods)

    def run(self):
        self.app.run(port=self.port)
