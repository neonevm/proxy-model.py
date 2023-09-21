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
from github_api_client import GithubClient

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

UNISWAP_V2_CORE_COMMIT = 'latest'
UNISWAP_V2_CORE_IMAGE = f'neonlabsorg/uniswap-v2-core:{UNISWAP_V2_CORE_COMMIT}'

FAUCET_COMMIT = 'latest'

NEON_TESTS_IMAGE = "neonlabsorg/neon_tests:latest"

CONTAINERS = ['proxy', 'solana', 'neon_test_invoke_program_loader',
              'dbcreation', 'faucet', 'gas_tank', 'indexer']

docker_client = docker.APIClient()
terraform = Terraform(working_dir=pathlib.Path(
    __file__).parent / "full_test_suite")


def docker_compose(args: str):
    command = f'docker-compose {args}'
    click.echo(f"run command: {command}")
    out = subprocess.run(command, shell=True)
    click.echo("return code: " + str(out.returncode))
    if out.returncode != 0:
        raise RuntimeError(f"Command {command} failed. Err: {out.stderr}")

    return out


def check_neon_evm_tag(tag):
    response = requests.get(
        url=f"https://registry.hub.docker.com/v2/repositories/neonlabsorg/evm_loader/tags/{tag}")
    if response.status_code != 200:
        raise RuntimeError(
            f"evm_loader image with {tag} tag isn't found. Response: {response.json()}")


def is_neon_evm_branch_exist(branch):
    if branch:
        proxy_branches_obj = requests.get(
            "https://api.github.com/repos/neonlabsorg/neon-evm/branches?per_page=100").json()
        proxy_branches = [item["name"] for item in proxy_branches_obj]

        if branch in proxy_branches:
            click.echo(f"The same branch {branch} is found in neon_evm repository")
            return True
    else:
        return False


def update_neon_evm_tag_if_same_branch_exists(branch, neon_evm_tag):
    if is_neon_evm_branch_exist(branch):
        neon_evm_tag = branch.split('/')[-1]
        check_neon_evm_tag(neon_evm_tag)
    return neon_evm_tag


@cli.command(name="build_docker_image")
@click.option('--neon_evm_tag', help="the neonlabsorg/evm_loader image tag that will be used for the build")
@click.option('--proxy_tag', help="a tag to be generated for the proxy image")
@click.option('--head_ref_branch')
@click.option('--skip_pull', is_flag=True, default=False, help="skip pulling of docker images from the docker-hub")
def build_docker_image(neon_evm_tag, proxy_tag, head_ref_branch, skip_pull):
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
                 "PROXY_REVISION": proxy_tag}

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


@cli.command(name="get_container_logs")
def get_all_containers_logs():
    home_path = os.environ.get("HOME")
    artifact_logs = "./logs"
    ssh_key = f"{home_path}/.ssh/ci-stands"
    os.mkdir(artifact_logs)
    proxy_ip = os.environ.get("PROXY_IP")
    solana_ip = os.environ.get("SOLANA_IP")

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
    project_name = proxy_tag
    cleanup_docker(project_name)

    if not skip_pull:
        click.echo('pull docker images...')
        out = docker_compose(f"-p {project_name} -f docker-compose/docker-compose-ci.yml pull")
        click.echo(out)
    else:
        click.echo('skip pulling of docker images')

    try:
        docker_compose(f"-p {project_name} -f docker-compose/docker-compose-ci.yml up -d")
    except:
        raise RuntimeError("Docker-compose failed to start")

    containers = ["".join(item['Names']).replace("/", "")
                  for item in docker_client.containers() if item['State'] == 'running']
    click.echo(f"Running containers: {containers}")

    for service_name in ['SOLANA', 'PROXY', 'FAUCET']:
        wait_for_service(project_name, service_name)

    if not skip_uniswap:
        run_uniswap_test(project_name)

    if test_files is None:
        test_list = get_test_list(project_name)
    else:
        test_list = test_files.split(',')

    prepare_run_test(project_name)

    errors_count = 0
    for file in test_list:
        errors_count += run_test(project_name, file)

    if errors_count > 0:
        raise RuntimeError(f"Tests failed! Errors count: {errors_count}")


def get_test_list(project_name):
    inst = docker_client.exec_create(
        f"{project_name}_proxy_1", 'find . -type f -name "test_*.py" -printf "%f\n"')
    out = docker_client.exec_start(inst['Id'])
    test_list = out.decode('utf-8').strip().split('\n')
    return test_list


def prepare_run_test(project_name):
    inst = docker_client.exec_create(
        f"{project_name}_proxy_1", './proxy/prepare-deploy-test.sh')
    out, test_logs = docker_client.exec_start(inst['Id'], demux=True)
    test_logs = test_logs.decode('utf-8')
    click.echo(out)
    click.echo(test_logs)


def run_test(project_name, file_name):
    click.echo(f"Running {file_name} tests")
    env = {"SKIP_PREPARE_DEPLOY_TEST": "YES", "TESTNAME": file_name}
    inst = docker_client.exec_create(
        f"{project_name}_proxy_1", './proxy/deploy-test.sh', environment=env)
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
@click.option('--proxy_tag', help="the neonlabsorg/proxy image tag")
def dump_apps_logs(proxy_tag):
    for container in [f"{proxy_tag}_{item}_1" for item in CONTAINERS]:
        dump_docker_logs(container)


def dump_docker_logs(container):
    try:
        logs = docker_client.logs(container).decode("utf-8")
        with open(f"{container}.log", "w") as file:
            file.write(logs)
    except (docker.errors.NotFound):
        click.echo(f"Container {container} does not exist")


@cli.command(name="stop_containers")
@click.option('--proxy_tag', help="the neonlabsorg/proxy image tag")
def stop_containers(proxy_tag):
    cleanup_docker(proxy_tag)


def cleanup_docker(project_name):
    click.echo(f"Cleanup docker-compose...")

    docker_compose(f"-p {project_name} -f docker-compose/docker-compose-ci.yml down -t 1")
    click.echo(f"Cleanup docker-compose done.")

    click.echo(f"Removing temporary data volumes...")
    command = "docker volume prune -f"
    subprocess.run(command, shell=True)
    click.echo(f"Removing temporary data done.")


def get_service_url(project_name: str, service_name: str):
    inspect_out = docker_client.inspect_container(f"{project_name}_proxy_1")
    env = inspect_out["Config"]["Env"]
    service_url = ""
    for item in env:
        if f"{service_name}_URL=" in item:
            service_url = item.replace(f"{service_name}_URL=", "")
            break
    click.echo(f"service_url: {service_url}")
    return service_url


def wait_for_service(project_name: str, service_name: str):
    service_url = get_service_url(project_name, service_name)
    service_info = urlparse(service_url)
    service_ip, service_port = service_info.hostname, service_info.port

    command = f'docker exec {project_name}_proxy_1 nc -zvw1 {service_ip} {service_port}'
    timeout_sec = 120
    start_time = time.time()
    while True:
        if time.time() - start_time > timeout_sec:
            raise RuntimeError(f'Service {service_name} {service_url} is unavailable - time is over')
        try:
            if subprocess.run(command, shell=True, capture_output=True, text=True).returncode == 0:
                click.echo(f"Service {service_name} is available")
                break
            else:
                click.echo(f"Service {service_name} {service_url} is unavailable - sleeping")
        except:
            raise RuntimeError(f"Error during run command {command}")
        time.sleep(1)


def run_uniswap_test(project_name):
    faucet_name = 'FAUCET'
    faucet_url = get_service_url(project_name, faucet_name)
    os.environ[f'{faucet_name}_URL'] = faucet_url

    docker_client.pull(UNISWAP_V2_CORE_IMAGE)
    command = f'docker run --rm --network=container:{project_name}_proxy_1 -e {faucet_name}_URL \
        --entrypoint ./deploy-test.sh {UNISWAP_V2_CORE_IMAGE} all 2>&1'
    out = subprocess.run(command, shell=True)
    click.echo("return code: " + str(out.returncode))
    if out.returncode != 0:
        raise RuntimeError(f"Uniswap tests failed. Err: {out.stderr}")


@cli.command(name="trigger_dapps_tests", help="Run dapps tests workflow")
@click.option("--solana_ip", help="solana ip")
@click.option("--proxy_ip", help="proxy ip")
@click.option('--pr_url_for_report', default="", help="Url to send the report as comment for PR")
@click.option('--token', help="github token")
def trigger_dapps_tests(solana_ip, proxy_ip, pr_url_for_report, token):
    github = GithubClient(token)

    runs_before = github.get_dapps_runs_list()
    runs_count_before = github.get_dapps_runs_count()
    proxy_url = f"http://{proxy_ip}:9090/solana"
    solana_url = f"http://{solana_ip}:8899/"
    faucet_url = f"http://{proxy_ip}:3333/"

    github.run_dapps_dispatches(proxy_url, solana_url, faucet_url, pr_url_for_report)
    wait_condition(lambda: github.get_dapps_runs_count() > runs_count_before, timeout_sec=180)

    runs_after = github.get_dapps_runs_list()
    run_id = list(set(runs_after) - set(runs_before))[0]
    link = f"https://github.com/neonlabsorg/neon-tests/actions/runs/{run_id}"
    click.echo(f"Dapps tests run link: {link}")
    click.echo("Waiting completed status...")
    wait_condition(lambda: github.get_dapps_run_info(run_id)["status"] == "completed", timeout_sec=7200, delay=5)

    if github.get_dapps_run_info(run_id)["conclusion"] == "success":
        click.echo("Dapps tests passed successfully")
    else:
        raise RuntimeError(f"Dapps tests failed! See {link}")


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


def wait_condition(func_cond, timeout_sec=60, delay=0.5):
    start_time = time.time()
    while True:
        if time.time() - start_time > timeout_sec:
            raise RuntimeError(f"The condition not reached within {timeout_sec} sec")
        try:
            if func_cond():
                break
        except:
            raise
        time.sleep(delay)


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
