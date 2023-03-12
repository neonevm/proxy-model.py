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



The repository contains sources for several services with similar logic: proxy, indexer, 
and airdropper.

Airdropper is a service to analyze transactions with NeonEVM instructions and looks for 
liquidity transfers into Neon. The service rewards with some amount of NEON the users
 that make such transfers.
The service takes configuration through environment variables. Additional to the common 
proxy environment the service takes the next variables:
 - FAUCET_URL - URL to the faucet service for distributing NEON tokens to the users
 - INDEXER_ERC20_WRAPPER_WHITELIST - the comma-separated list of ERC20ForSpl wrapped
   tokens for transfer which the service rewards the users. The airdropper looks for 
   the first transfers of such tokens from Solana to Neon (those transfers that lead 
   to creating Neon accounts). It can contain the `ANY` value to accept any token.
 - PORTAL_BRIDGE_CONTRACTS - the comma-separated list of Portal Bridge contracts.
 - PORTAL_BRIDGE_TOKENS_WHITELIST - the whitelist of tokens for the transfer of which 
   to airdrop NEONs. This set should contain the next items: "tokenChain:tokenAddress", where:
    - `tokenChain` is an original token chain number in terms of Portal bridge numbers
    - `tokenAddress` is the address of the token in hexadecimal lowercase form with a '0x' prefix

Note: PORTAL_BRIDGE_CONTRACTS & PORTAL_BRIDGE_TOKENS_WHITELIST should be specified together.
If they are missed the airdropper doesn't analyze Portal Bridge transfers.