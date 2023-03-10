import os
import re
import time
import sys
import docker
import subprocess
import pathlib
import requests
import json
import typing as tp
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

NEON_TESTS_IMAGE = "neonlabsorg/neon_tests:latest"

CONTAINERS = ['proxy', 'solana', 'neon_test_invoke_program_loader',
              'dbcreation', 'faucet', 'airdropper', 'indexer']

docker_client = docker.APIClient()
terraform = Terraform(working_dir=pathlib.Path(
    __file__).parent / "full_test_suite")


def docker_compose(args: str):
    command = f'docker-compose {args}'
    click.echo(f"run command: {command}")
    out = subprocess.run(command, shell=True)
    return out


def check_neon_evm_tag(tag):
    response = requests.get(
        url=f"https://registry.hub.docker.com/v2/repositories/neonlabsorg/evm_loader/tags/{tag}")
    if response.status_code != 200:
        raise RuntimeError(
            f"evm_loader image with {tag} tag isn't found. Response: {response.json()}")


def update_neon_evm_tag_if_same_branch_exists(branch, neon_evm_tag):
    if branch != "":
        proxy_branches_obj = requests.get(
            "https://api.github.com/repos/neonlabsorg/neon-evm/branches?per_page=100").json()
        proxy_branches = [item["name"] for item in proxy_branches_obj]
        if branch in proxy_branches:
            click.echo(f"The same branch {branch} is found in neon_evm repository")
            neon_evm_tag = branch.split('/')[-1]
            check_neon_evm_tag(neon_evm_tag)
    return neon_evm_tag


@cli.command(name="build_docker_image")
@click.option('--neon_evm_tag', help="the neonlabsorg/evm_loader image tag that will be used for the build")
@click.option('--proxy_tag', help="a tag to be generated for the proxy image")
@click.option('--head_ref_branch')
@click.option('--skip_pull', is_flag=True, default=False, help="skip pulling of docker images from the docker-hub")
def build_docker_image(neon_evm_tag, proxy_tag, head_ref_branch, skip_pull):
    if head_ref_branch is not None:
        neon_evm_tag = update_neon_evm_tag_if_same_branch_exists(head_ref_branch, neon_evm_tag)
    neon_evm_image = f'neonlabsorg/evm_loader:{neon_evm_tag}'
    click.echo(f"neon-evm image: {neon_evm_image}")
    neon_test_invoke_program_image = "neonlabsorg/neon_test_invoke_program:develop"
    if not skip_pull:
        click.echo('pull docker images...')
        out = docker_client.pull(neon_evm_image, stream=True, decode=True)
        process_output(out)

        out = docker_client.pull(neon_test_invoke_program_image, stream=True, decode=True)
        process_output(out)
    else:
        click.echo('skip pulling of docker images')

    buildargs = {"NEON_EVM_COMMIT": neon_evm_tag,
                 "PROXY_REVISION": proxy_tag,
                 "PROXY_LOG_CFG": "log_cfg.json"}

    click.echo("Start build")

    output = docker_client.build(
        tag=f"{IMAGE_NAME}:{proxy_tag}", buildargs=buildargs, path="./", decode=True, network_mode='host')
    process_output(output)


@cli.command(name="publish_image")
@click.option('--proxy_tag')
def publish_image(proxy_tag):
    docker_client.login(username=DOCKER_USERNAME, password=DOCKER_PASSWORD)
    out = docker_client.push(f"{IMAGE_NAME}:{proxy_tag}", decode=True, stream=True)
    process_output(out)


@cli.command(name="finalize_image")
@click.option('--head_ref_branch')
@click.option('--github_ref')
@click.option('--proxy_tag')
def finalize_image(head_ref_branch, github_ref, proxy_tag):
    branch = github_ref.replace("refs/heads/", "")
    if 'refs/tags/' in branch:
        tag = branch.replace("refs/tags/", "")
    elif branch == 'master':
        tag = 'stable'
    elif branch == 'develop':
        tag = 'latest'
    elif head_ref_branch != "":
        tag = head_ref_branch.split('/')[-1]
    else:
        tag = branch.split('/')[-1]

    click.echo(f"The tag for publishing: {tag}")
    docker_client.login(username=DOCKER_USERNAME, password=DOCKER_PASSWORD)
    out = docker_client.pull(f"{IMAGE_NAME}:{proxy_tag}", decode=True, stream=True)
    process_output(out)
    docker_client.tag(f"{IMAGE_NAME}:{proxy_tag}", f"{IMAGE_NAME}:{tag}")
    out = docker_client.push(f"{IMAGE_NAME}:{tag}", decode=True, stream=True)
    process_output(out)


@cli.command(name="terraform_infrastructure")
@click.option('--head_ref_branch')
@click.option('--github_ref_name')
@click.option('--neon_evm_tag')
@click.option('--proxy_tag')
@click.option('--run_number')
def terraform_build_infrastructure(head_ref_branch, github_ref_name, proxy_tag, neon_evm_tag, run_number):
    branch = head_ref_branch if head_ref_branch != "" else github_ref_name
    neon_evm_tag = update_neon_evm_tag_if_same_branch_exists(head_ref_branch, neon_evm_tag)
    os.environ["TF_VAR_branch"] = branch
    os.environ["TF_VAR_proxy_model_commit"] = proxy_tag
    os.environ["TF_VAR_neon_evm_commit"] = neon_evm_tag
    os.environ["TF_VAR_faucet_model_commit"] = FAUCET_COMMIT
    thstate_key = f'{TFSTATE_KEY_PREFIX}{proxy_tag}-{run_number}'

    backend_config = {"bucket": TFSTATE_BUCKET,
                      "key": thstate_key, "region": TFSTATE_REGION}
    terraform.init(backend_config=backend_config)
    return_code, stdout, stderr = terraform.apply(skip_plan=True)
    click.echo(f"code: {return_code}")
    click.echo(f"stdout: {stdout}")
    click.echo(f"stderr: {stderr}")
    with open(f"terraform.log", "w") as file:
        file.write(stdout)
        file.write(stderr)
    if return_code != 0:
        print("Terraform infrastructure is not built correctly")
        sys.exit(1)
    output = terraform.output(json=True)
    click.echo(f"output: {output}")
    proxy_ip = output["proxy_ip"]["value"]
    solana_ip = output["solana_ip"]["value"]
    infra = dict(solana_ip=solana_ip, proxy_ip=proxy_ip)
    set_github_env(infra)


def set_github_env(envs: tp.Dict, upper=True) -> None:
    """Set environment for github action"""
    path = os.getenv("GITHUB_ENV", str())
    if os.path.exists(path):
        with open(path, "a") as env_file:
            for key, value in envs.items():
                env_file.write(f"\n{key.upper() if upper else key}={str(value)}")


@cli.command(name="destroy_terraform")
@click.option('--proxy_tag')
@click.option('--run_number')
def destroy_terraform(proxy_tag, run_number):
    thstate_key = f'{TFSTATE_KEY_PREFIX}{proxy_tag}-{run_number}'

    backend_config = {"bucket": TFSTATE_BUCKET,
                      "key": thstate_key, "region": TFSTATE_REGION}
    terraform.init(backend_config=backend_config)
    terraform.destroy()


@cli.command(name="openzeppelin")
@click.option('--run_number')
def openzeppelin_test(run_number):
    container_name = f'fts_{run_number}'
    fts_threshold = 2370
    os.environ["FTS_CONTAINER_NAME"] = container_name
    os.environ["FTS_IMAGE"] = NEON_TESTS_IMAGE
    os.environ["FTS_USERS_NUMBER"] = '15'
    os.environ["FTS_JOBS_NUMBER"] = '8'
    os.environ["NETWORK_NAME"] = f'full-test-suite-{run_number}'
    os.environ["NETWORK_ID"] = '111'
    os.environ["REQUEST_AMOUNT"] = '20000'
    os.environ["USE_FAUCET"] = 'true'

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
    command = f'docker cp {container_name}:/opt/neon-tests/allure-reports.tar.gz ./'
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


@cli.command(name="basic_tests")
@click.option('--run_number')
def run_basic_tests(run_number):
    click.echo('pull docker images...')
    out = docker_client.pull(NEON_TESTS_IMAGE, stream=True, decode=True)
    process_output(out)
    env = {
        "PROXY_IP": os.environ.get("PROXY_IP"),
        "SOLANA_IP": os.environ.get("SOLANA_IP")
    }
    container_name = f"basic_tests-{run_number}"
    docker_client.create_container(NEON_TESTS_IMAGE, command="/bin/bash", name=container_name,
                                   detach=True, tty=True)
    docker_client.start(container_name)
    inst = docker_client.exec_create(
        container_name, './clickfile.py run basic -n aws --numprocesses 4', environment=env)

    out = docker_client.exec_start(inst['Id'], stream=True)
    failed_tests = 0
    for line in out:
        click.echo(line.decode())
        if " ERROR " in line.decode() or " FAILED " in line.decode():
            failed_tests += 1
    if failed_tests > 0:
        raise RuntimeError(f"Tests failed! Errors count: {failed_tests}")


@cli.command(name="remove_basic_test_container")
@click.option('--run_number')
def remove_basic_test_container(run_number):
    container_name = f"basic_tests-{run_number}"
    docker_client.stop(container_name)
    docker_client.remove_container(container_name)


def upload_remote_logs(ssh_client, service, artifact_logs):
    scp_client = SCPClient(transport=ssh_client.get_transport())
    click.echo(f"Upload logs for service: {service}")
    ssh_client.exec_command(f"touch /tmp/{service}.log.bz2")
    stdin, stdout, stderr = ssh_client.exec_command(
        f'sudo docker logs {service} 2>&1 | pbzip2 -f > /tmp/{service}.log.bz2')
    print(stdout.read())
    print(stderr.read())
    stdin, stdout, stderr = ssh_client.exec_command(f'ls -lh /tmp/{service}.log.bz2')
    print(stdout.read())
    print(stderr.read())
    scp_client.get(f'/tmp/{service}.log.bz2', artifact_logs)


@cli.command(name="deploy_check")
@click.option('--proxy_tag', help="the neonlabsorg/proxy image tag")
@click.option('--neon_evm_tag', help="the neonlabsorg/evm_loader image tag")
@click.option('--head_ref_branch')
@click.option('--skip_uniswap', is_flag=True, show_default=True, default=False, help="flag for skipping uniswap tests")
@click.option('--test_files', help="comma-separated file names if you want to run a specific list of tests")
@click.option('--skip_pull', is_flag=True, default=False, help="skip pulling of docker images from the docker-hub")
def deploy_check(proxy_tag, neon_evm_tag, head_ref_branch, skip_uniswap, test_files, skip_pull):
    if head_ref_branch is not None:
        neon_evm_tag = update_neon_evm_tag_if_same_branch_exists(head_ref_branch, neon_evm_tag)

    os.environ["REVISION"] = proxy_tag
    os.environ["NEON_EVM_COMMIT"] = neon_evm_tag
    os.environ["FAUCET_COMMIT"] = FAUCET_COMMIT

    cleanup_docker()

    if not skip_pull:
        click.echo('pull docker images...')
        out = docker_compose(f"-f proxy/docker-compose-test.yml pull")
        click.echo(out)
    else:
        click.echo('skip pulling of docker images')

    try:
        docker_compose(f"-f proxy/docker-compose-test.yml up -d")
    except:
        raise RuntimeError("Docker-compose failed to start")

    containers = ["".join(item['Names']).replace("/", "")
                  for item in docker_client.containers() if item['State'] == 'running']
    click.echo(f"Running containers: {containers}")

    wait_for_faucet()

    if not skip_uniswap:
        run_uniswap_test()

    if test_files is None:
        test_list = get_test_list()
    else:
        test_list = test_files.split(',')

    prepare_run_test()

    errors_count = 0
    for file in test_list:
        errors_count += run_test(file)

    if errors_count > 0:
        raise RuntimeError(f"Tests failed! Errors count: {errors_count}")


def get_test_list():
    inst = docker_client.exec_create(
        "proxy", 'find . -type f -name "test_*.py" -printf "%f\n"')
    out = docker_client.exec_start(inst['Id'])
    test_list = out.decode('utf-8').strip().split('\n')
    return test_list


def prepare_run_test():
    inst = docker_client.exec_create(
        "proxy", './proxy/prepare-deploy-test.sh')
    out, test_logs = docker_client.exec_start(inst['Id'], demux=True)
    test_logs = test_logs.decode('utf-8')
    click.echo(out)
    click.echo(test_logs)


def run_test(file_name):
    click.echo(f"Running {file_name} tests")
    env = {"SKIP_PREPARE_DEPLOY_TEST": "YES", "TESTNAME": file_name}
    inst = docker_client.exec_create(
        "proxy", './proxy/deploy-test.sh', environment=env)
    out, test_logs = docker_client.exec_start(inst['Id'], demux=True)
    test_logs = test_logs.decode('utf-8')
    click.echo(out)
    click.echo(test_logs)
    errors_count = 0
    for line in test_logs.split('\n'):
        if re.match(r"FAILED \(.+=\d+", line):
            errors_count += int(re.search(r"\d+", line).group(0))
    return errors_count


@cli.command(name="dump_apps_logs")
def dump_apps_logs():
    for container in CONTAINERS:
        dump_docker_logs(container)


def dump_docker_logs(container):
    try:
        logs = docker_client.logs(container).decode("utf-8")
        with open(f"{container}.log", "w") as file:
            file.write(logs)
    except (docker.errors.NotFound):
        click.echo(f"Container {container} does not exist")


@cli.command(name="stop_containers")
def stop_containers():
    cleanup_docker()


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
            raise RuntimeError(f'Faucet {faucet_url} is unavailable - time is over')
        try:
            if subprocess.run(
                command, shell=True, capture_output=True, text=True).returncode == 0:
                click.echo(f"Faucet {faucet_url} is available")
                break
            else:
                click.echo(f"Faucet {faucet_url} is unavailable - sleeping")
        except:
            raise RuntimeError(f"Error during run command {command}")
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


def process_output(output):
    for line in output:
        if line:
            errors = set()
            try:
                if "status" in line:
                    click.echo(line["status"])

                elif "stream" in line:
                    stream = re.sub("^\n", "", line["stream"])
                    stream = re.sub("\n$", "", stream)
                    stream = re.sub("\n(\x1B\[0m)$", "\\1", stream)
                    if stream:
                        click.echo(stream)

                elif "aux" in line:
                    if "Digest" in line["aux"]:
                        click.echo("digest: {}".format(line["aux"]["Digest"]))

                    if "ID" in line["aux"]:
                        click.echo("ID: {}".format(line["aux"]["ID"]))

                else:
                    click.echo("not recognized (1): {}".format(line))

                if "error" in line:
                    errors.add(line["error"])

                if "errorDetail" in line:
                    errors.add(line["errorDetail"]["message"])

                    if "code" in line:
                        error_code = line["errorDetail"]["code"]
                        errors.add("Error code: {}".format(error_code))

            except ValueError as e:
                click.echo("not recognized (2): {}".format(line))

            if errors:
                message = "problem executing Docker: {}".format(". ".join(errors))
                raise SystemError(message)


if __name__ == "__main__":
    cli()
