import os
import re
import time
import sys
import docker
import subprocess
import pathlib
import requests
import json
from urllib.parse import urlparse
from python_terraform import Terraform
from paramiko import SSHClient
from scp import SCPClient
try:
    import click
except ImportError:
    print("Please install click library: pip install click==8.0.3")
    sys.exit(1)


@click.group()
def cli():
    pass


ERR_MSG_TPL = {
    "blocks": [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": ""},
        },
        {"type": "divider"},
    ]
}

DOCKER_USERNAME = os.environ.get("DOCKER_USERNAME")
DOCKER_PASSWORD = os.environ.get("DOCKER_PASSWORD")

TFSTATE_BUCKET = "nl-ci-stands"
TFSTATE_KEY_PREFIX = "tests/test-"
TFSTATE_REGION = "us-east-2"
IMAGE_NAME = "neonlabsorg/proxy"

UNISWAP_V2_CORE_COMMIT = 'stable'
UNISWAP_V2_CORE_IMAGE = f'neonlabsorg/uniswap-v2-core:{UNISWAP_V2_CORE_COMMIT}'

FAUCET_COMMIT = 'latest'

FTS_NAME = "neonlabsorg/full_test_suite:develop"

docker_client = docker.APIClient()
terraform = Terraform(working_dir=pathlib.Path(
    __file__).parent / "full_test_suite")


def docker_compose(args: str):
    command = f'docker-compose {args}'
    click.echo(f"run command: {command}")
    out = subprocess.run(command, shell=True)
    return out


def get_neon_evm_tag(proxy_tag):
    proxy_tag_withot_prefix = re.sub('-.*', '', proxy_tag)
    evm_tag = re.sub('\d{1,2}$', 'x', proxy_tag_withot_prefix)
    response = requests.get(
        url=f"https://registry.hub.docker.com/v2/repositories/neonlabsorg/evm_loader/tags/{evm_tag}")
    if response.status_code != 200:
        raise RuntimeError(
            f"evm_loader image with {evm_tag} tag isn't found. Response: {response.json()}")
    click.echo(f"Neon evm mage with tag {evm_tag} will be used")
    return evm_tag


@cli.command(name="build_docker_image")
@click.option('--neon_evm_tag')
@click.option('--proxy_tag')
@click.option('--github_sha')
def build_docker_image(neon_evm_tag, proxy_tag, github_sha):
    if re.match(r"v\d{1,2}\.\d{1,2}\.\d{1,2}\.*", proxy_tag):
        neon_evm_tag = get_neon_evm_tag(proxy_tag)

    neon_evm_image = f'neonlabsorg/evm_loader:{neon_evm_tag}'
    neon_test_invoke_program_image = "neonlabsorg/neon_test_invoke_program:develop"
    docker_client.pull(neon_evm_image)
    docker_client.pull(neon_test_invoke_program_image)

    buildargs = {"NEON_EVM_COMMIT": neon_evm_tag,
                 "PROXY_REVISION": github_sha,
                 "PROXY_LOG_CFG": "log_cfg.json"}

    tag = f"{IMAGE_NAME}:{github_sha}"
    click.echo("start build")
    output = docker_client.build(tag=tag, buildargs=buildargs, path="./")
    for line in output:
        if 'stream' in str(line):
            click.echo(str(line).strip('\n'))


@cli.command(name="publish_image")
@click.option('--github_sha')
def publish_image(github_sha):
    docker_client.login(username=DOCKER_USERNAME, password=DOCKER_PASSWORD)
    out = docker_client.push(f"{IMAGE_NAME}:{github_sha}")
    if "error" in out:
        raise RuntimeError(
            f"Push {IMAGE_NAME}:{github_sha} finished with error: {out}")


@cli.command(name="finalize_image")
@click.option('--head_ref_branch')
@click.option('--github_ref')
@click.option('--github_sha')
def finalize_image(head_ref_branch, github_ref, github_sha):
    if 'refs/tags/' in github_ref:
        tag = github_ref.replace("refs/tags/", "")
    elif github_ref == 'refs/heads/master':
        tag = 'stable'
    elif github_ref == 'refs/heads/develop':
        tag = 'latest'
    else:
        tag = head_ref_branch.split('/')[-1]

    docker_client.login(username=DOCKER_USERNAME, password=DOCKER_PASSWORD)
    out = docker_client.pull(f"{IMAGE_NAME}:{github_sha}")
    if "error" in out:
        raise RuntimeError(
            f"Pull {IMAGE_NAME}:{github_sha} finished with error: {out}")

    docker_client.tag(f"{IMAGE_NAME}:{github_sha}", f"{IMAGE_NAME}:{tag}")
    out = docker_client.push(f"{IMAGE_NAME}:{tag}")
    if "error" in out:
        raise RuntimeError(
            f"Push {IMAGE_NAME}:{tag} finished with error: {out}")


@cli.command(name="terraform_infrastructure")
@click.option('--head_ref_branch')
@click.option('--github_ref_name')
@click.option('--github_sha')
@click.option('--neon_evm_tag')
@click.option('--proxy_tag')
@click.option('--run_number')
def terraform_build_infrastructure(head_ref_branch, github_ref_name, github_sha, proxy_tag, neon_evm_tag, run_number):

    branch = head_ref_branch if head_ref_branch is not None else github_ref_name
    os.environ["TF_VAR_branch"] = branch
    os.environ["TF_VAR_proxy_model_commit"] = proxy_tag
    os.environ["TF_VAR_neon_evm_commit"] = neon_evm_tag
    os.environ["TF_VAR_faucet_model_commit"] = FAUCET_COMMIT
    thstate_key = f'{TFSTATE_KEY_PREFIX}{github_sha}-{run_number}'

    backend_config = {"bucket": TFSTATE_BUCKET,
                      "key": thstate_key, "region": TFSTATE_REGION}
    terraform.init(backend_config=backend_config)
    return_code, stdout, stderr = terraform.apply(skip_plan=True)
    click.echo(f"code: {return_code}")
    click.echo(f"stdout: {stdout}")
    click.echo(f"stderr: {stderr}")


@cli.command(name="destroy_terraform")
@click.option('--github_sha')
@click.option('--run_number')
def destroy_terraform(github_sha, run_number):
    thstate_key = f'{TFSTATE_KEY_PREFIX}{github_sha}-{run_number}'

    backend_config = {"bucket": TFSTATE_BUCKET,
                      "key": thstate_key, "region": TFSTATE_REGION}
    terraform.init(backend_config=backend_config)
    terraform.destroy()


@cli.command(name="openzeppelin")
@click.option('--run_number')
def openzeppelin_test(run_number):
    container_name = f'fts_{run_number}'
    fts_threshold = 1920
    os.environ["FTS_CONTAINER_NAME"] = container_name
    os.environ["FTS_IMAGE"] = FTS_NAME
    os.environ["FTS_USERS_NUMBER"] = '15'
    os.environ["FTS_JOBS_NUMBER"] = '8'
    os.environ["NETWORK_NAME"] = f'full-test-suite-{run_number}'
    os.environ["NETWORK_ID"] = '111'
    os.environ["REQUEST_AMOUNT"] = '20000'
    os.environ["USE_FAUCET"] = 'true'

    output = terraform.output(json=True)
    click.echo(f"output: {output}")
    os.environ["PROXY_IP"] = output["proxy_ip"]["value"]
    os.environ["SOLANA_IP"] = output["solana_ip"]["value"]
    proxy_ip = os.environ.get("PROXY_IP")
    solana_ip = os.environ.get("SOLANA_IP")

    os.environ["PROXY_URL"] = f"http://{proxy_ip}:9090/solana"
    os.environ["FAUCET_URL"] = f"http://{proxy_ip}:3333/request_neon"
    os.environ["SOLANA_URL"] = f"http://{solana_ip}:8899"

    click.echo(f"Env: {os.environ}")
    click.echo(f"Running tests....")

    docker_compose("-f docker-compose/docker-compose-full-test-suite.yml pull")
    fts_result = docker_compose(
        "-f docker-compose/docker-compose-full-test-suite.yml up")
    click.echo(fts_result)
    command = f'docker cp {container_name}:/opt/allure-reports.tar.gz ./'
    click.echo(f"run command: {command}")
    subprocess.run(command, shell=True)

    dump_docker_logs(container_name)
    home_path = os.environ.get("HOME")
    artifact_logs = "./logs"
    ssh_key = f"{home_path}/.ssh/ci-stands"
    os.mkdir(artifact_logs)

    subprocess.run(
        f'ssh-keyscan -H {solana_ip} >> {home_path}/.ssh/known_hosts', shell=True)
    subprocess.run(
        f'ssh-keyscan -H {proxy_ip} >> {home_path}/.ssh/known_hosts', shell=True)
    ssh_client = SSHClient()
    ssh_client.load_system_host_keys()
    ssh_client.connect(solana_ip, username='ubuntu',
                       key_filename=ssh_key, timeout=120)

    upload_remote_logs(ssh_client, "solana", artifact_logs)

    ssh_client.connect(proxy_ip, username='ubuntu',
                       key_filename=ssh_key, timeout=120)
    services = ["postgres", "dbcreation", "indexer", "proxy", "faucet"]
    for service in services:
        upload_remote_logs(ssh_client, service, artifact_logs)
    dump_docker_logs(container_name)
    docker_compose(
        "-f docker-compose/docker-compose-full-test-suite.yml rm -f")
    check_tests_results(fts_threshold, f"{container_name}.log")


def check_tests_results(fts_threshold, log_file):
    passing_test_count = 0
    with open(log_file, "r") as file:
        while True:
            line = file.readline()
            if not line:
                break
            if re.match(r".*Passing - ", line):
                passing_test_count = int(line.split('-')[1].strip())
                break
    if passing_test_count < fts_threshold:
        raise RuntimeError(
            f"Tests failed: Passing - {passing_test_count}\n Threshold - {fts_threshold}")


def upload_remote_logs(ssh_client, service, artifact_logs):
    scp_client = SCPClient(transport=ssh_client.get_transport())
    click.echo(f"Upload logs for service: {service}")
    ssh_client.exec_command(
        f'sudo docker logs {service} 2>&1 | pbzip2 > /tmp/{service}.log.bz2')
    scp_client.get(f'/tmp/{service}.log.bz2', artifact_logs)


@cli.command(name="deploy_check")
@click.option('--proxy_tag')
@click.option('--neon_evm_tag')
def deploy_check(proxy_tag, neon_evm_tag):
    os.environ["REVISION"] = proxy_tag
    os.environ["NEON_EVM_COMMIT"] = neon_evm_tag
    os.environ["FAUCET_COMMIT"] = FAUCET_COMMIT
    cleanup_docker()

    try:
        docker_compose("-f proxy/docker-compose-test.yml up -d")
    except:
        raise "Docker-compose failed to start"

    containers = ["".join(item['Names']).replace("/", "")
                  for item in docker_client.containers() if item['State'] == 'running']
    click.echo(f"Running containers: {containers}")

    wait_for_faucet()
    run_uniswap_test()

    for file in get_test_list():
        run_test(file)


def get_test_list():
    inst = docker_client.exec_create(
        "proxy", 'find . -type f -name "test_*.py" -printf "%f\n"')
    out = docker_client.exec_start(inst['Id'])
    test_list = out.decode('utf-8').strip().split('\n')
    return test_list


def run_test(file_name):
    click.echo(f"Running {file_name} tests")
    env = {"SKIP_PREPARE_DEPLOY_TEST": "YES", "TESTNAME": file_name}
    inst = docker_client.exec_create(
        "proxy", './proxy/deploy-test.sh', environment=env)
    out = docker_client.exec_start(inst['Id'])
    click.echo(out)


@cli.command(name="dump_apps_logs")
def dump_apps_logs():
    containers = ['proxy', 'solana', 'neon_test_invoke_program_loader',
                  'dbcreation', 'faucet', 'airdropper', 'indexer']
    for container in containers:
        dump_docker_logs(container)


def dump_docker_logs(container):
    try:
        logs = docker_client.logs(container).decode("utf-8")
        with open(f"{container}.log", "w") as file:
            file.write(logs)
    except (docker.errors.NotFound):
        click.echo(f"Container {container} does not exist")


def cleanup_docker():
    click.echo(f"Cleanup docker-compose...")
    docker_compose("-f proxy/docker-compose-test.yml down -t 1")
    click.echo(f"Cleanup docker-compose done.")
    click.echo(f"Removing temporary data volumes...")
    command = "docker volume prune -f"
    subprocess.run(command, shell=True)
    click.echo(f"Removing temporary data done.")


def get_faucet_url():
    inspect_out = docker_client.inspect_container("proxy")
    env = inspect_out["Config"]["Env"]
    faucet_url = ""
    for item in env:
        if "FAUCET_URL=" in item:
            faucet_url = item.replace("FAUCET_URL=", "")
            break
    click.echo(f"fauset_url: {faucet_url}")
    return faucet_url


def wait_for_faucet():
    faucet_url = get_faucet_url()
    faucet_ip, faucet_port = faucet_url.replace("http://", "").split(':')

    command = f'docker exec proxy nc -zvw1 {faucet_ip} {faucet_port}'
    timeout_sec = 120
    start_time = time.time()
    while True:
        if time.time() - start_time > timeout_sec:
            raise f'Faucet {faucet_url} is unavailable - time is over'
        try:
            if subprocess.run(
                    command, shell=True,  capture_output=True, text=True).returncode == 0:
                click.echo(f"Faucet {faucet_url} is available")
                break
            else:
                click.echo(f"Faucet {faucet_url} is unavailable - sleeping")
        except:
            raise f"Error during run command {command}"
        time.sleep(1)


def run_uniswap_test():
    faucet_url = get_faucet_url()
    os.environ["FAUCET_URL"] = faucet_url

    docker_client.pull(UNISWAP_V2_CORE_IMAGE)
    command = f'docker run --rm --network=container:proxy -e FAUCET_URL \
        --entrypoint ./deploy-test.sh {UNISWAP_V2_CORE_IMAGE} all 2>&1'
    subprocess.run(command, shell=True)


@cli.command(name="send_notification", help="Send notification to slack")
@click.option("-u", "--url", help="slack app endpoint url.")
@click.option("-b", "--build_url", help="github action test build url.")
def send_notification(url, build_url):
    tpl = ERR_MSG_TPL.copy()

    parsed_build_url = urlparse(build_url).path.split("/")
    build_id = parsed_build_url[-1]
    repo_name = f"{parsed_build_url[1]}/{parsed_build_url[2]}"

    tpl["blocks"][0]["text"]["text"] = (
        f"*Build <{build_url}|`{build_id}`> of repository `{repo_name}` is failed.*"
        f"\n<{build_url}|View build details>"
    )
    requests.post(url=url, data=json.dumps(tpl))


if __name__ == "__main__":
    cli()
