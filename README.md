Python prototype for Solana MetaMask proxy. Builded on https://github.com/abhinavsingh/proxy.py.git.

Requirements (for Ubuntu 18.04):
- python3
- python3-venv
- python3-dev
- gcc

For run internal implementation for Ethereum tokens start proxy with:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 -m proxy --hostname 127.0.0.1 --port 9090 --enable-web-server --plugins proxy.plugin.NeonRpcApiPlugin --num-workers=1
```

Then add network `http://localhost:9090/solana` into MetaMask
