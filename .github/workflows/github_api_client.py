import click
import requests
import os

NEON_TESTS_ENDPOINT = os.environ.get("NEON_TESTS_ENDPOINT")


class GithubClient():

    def __init__(self, token):
        self.headers = {"Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json"}

    def get_dapps_runs_list(self, branch="develop"):
        response = requests.get(
            f"{NEON_TESTS_ENDPOINT}/actions/workflows/dapps.yml/runs?branch={branch}", headers=self.headers)
        if response.status_code != 200:
            raise RuntimeError(f"Can't get dapps tests runs list. Error: {response.json()}")
        runs = [item['id'] for item in response.json()['workflow_runs']]
        return runs

    def get_dapps_runs_count(self, branch="develop"):
        response = requests.get(
            f"{NEON_TESTS_ENDPOINT}/actions/workflows/dapps.yml/runs?branch={branch}", headers=self.headers)
        return int(response.json()["total_count"])

    def run_dapps_dispatches(self, proxy_url, solana_url, faucet_url, pr_url_for_report, test_set, network_id='111',
                             branch='develop'):
        dapps = "" if test_set=='extendedFullTestSuite' else "aave,saddle,uniswap-v3"
        data = {"ref": branch,
                "inputs": {"proxy_url": proxy_url,
                           "solana_url": solana_url,
                           "faucet_url": faucet_url,
                           "network_id": network_id,
                           "pr_url_for_report": pr_url_for_report,
                           "dapps": dapps,
                           "network": "custom"}
                }
        click.echo(f"Sent data: {data}")
        click.echo(f"Headers: {self.headers}")
        response = requests.post(
            f"{NEON_TESTS_ENDPOINT}/actions/workflows/dapps.yml/dispatches", json=data, headers=self.headers)
        click.echo(f"Status code: {response.status_code}")
        if response.status_code != 204:
            raise RuntimeError(f"proxy-model.py action is not triggered. {response.text}")

    def get_dapps_run_info(self, id):
        response = requests.get(
            f"{NEON_TESTS_ENDPOINT}/actions/runs/{id}", headers=self.headers)
        return response.json()
