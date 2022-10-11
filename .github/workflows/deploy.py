import os
import time
import sys
import docker
import subprocess
from python_terraform import Terraform
try:
    import click
except ImportError:
    print("Please install click library: pip install click==8.0.3")
    sys.exit(1)


@click.group()
def cli():
    pass


githab_sha = "247f98b26f325530623ece2a749ffd1787ded7"
githab_build_id = 1
TFSTATE_BUCKET = "nl-ci-stands"
TFSTATE_KEY = f"tests/test-{githab_sha}-{githab_build_id}"
TFSTATE_REGION = "us-east-2"
IMAGE_NAME = "neonlabsorg/proxy"
DOCKER_USER = os.environ.get("DHUBU")
DOCKER_PASSWORD = os.environ.get("DHUBP")

UNISWAP_V2_CORE_COMMIT = 'stable'
UNISWAP_V2_CORE_IMAGE = f'neonlabsorg/uniswap-v2-core:{UNISWAP_V2_CORE_COMMIT}'
UNISWAP_TESTNAME = "test_UNISWAP.py"

docker_client = docker.APIClient()


@cli.command(name="build_docker_image")
@click.option('--neon_evm_commit')
@click.option('--github_sha')
def build_docker_image(neon_evm_commit, github_sha):
    neon_evm_image = f'neonlabsorg/evm_loader:{neon_evm_commit}'
    docker_client.pull(neon_evm_image)

    buildargs = {"NEON_EVM_COMMIT": neon_evm_commit,
                 "PROXY_REVISION": github_sha,
                 "PROXY_LOG_CFG": "log_cfg.json"}

    tag = f"{IMAGE_NAME}:{github_sha}"
    click.echo("start build")
    output = docker_client.build(tag=tag, buildargs=buildargs, path="./")
    for line in output:
        if 'stream' in str(line):
            click.echo(str(line).strip('\n'))


@cli.command(name="publish_image")
@click.option('--branch')
@click.option('--github_sha')
def publish_image(branch, github_sha):
    if branch == 'master':
        tag = 'stable'
    elif branch == 'develop':
        tag = 'latest'
    else:
        tag = branch.split('/')[-1]

    docker_client.login(username=DOCKER_USER, password=DOCKER_PASSWORD)

    docker_client.tag(f"{IMAGE_NAME}:{github_sha}", tag)
    docker_client.push(f"{IMAGE_NAME}:{tag}")

    docker_client.tag(f"{IMAGE_NAME}:{github_sha}", github_sha)
    docker_client.push(f"{IMAGE_NAME}:{github_sha}")


@cli.command(name="terraform")
def terraform_build_infrastructure():
    # app = cdktf.App()

    # a = cdktf.S3BackendProps(
    #     bucket=TFSTATE_BUCKET,
    #     key=TFSTATE_KEY,
    #     region=TFSTATE_REGION
    # )

    # app.synth()
    # print(app)
    t = Terraform()

    backend_config = {"bucket": TFSTATE_BUCKET,
                      "key": TFSTATE_KEY, "region": TFSTATE_REGION}
    return_code, stdout, stderr = t.init(backend_config=backend_config)

    print(return_code)
    print(stdout)
    print(stderr)
    t.destroy()


@cli.command(name="deploy_check")
@click.option('--neon_evm_commit')
@click.option('--github_sha')
def deploy_check(neon_evm_commit, github_sha):
    os.environ["REVISION"] = 'latest'  # TODO github_sha
    os.environ["NEON_EVM_COMMIT"] = neon_evm_commit
    os.environ["FAUCET_COMMIT"] = 'latest'

    containers = ['proxy', 'solana', 'proxy_program_loader',
                  'dbcreation', 'faucet', 'airdropper', 'indexer']
    for container in containers:
        dump_docker_logs(container)
    cleanup_docker()

    try:
        command = 'docker-compose -f proxy/docker-compose-test.yml up -d'
        subprocess.run(command, shell=True)
    except:
        raise "Docker-compose failed to start"

    containers = ["".join(item['Names']).replace("/", "")
                  for item in docker_client.containers() if item['State'] == 'running']
    click.echo(f"Running containers: {containers}")

    for container in containers:
        dump_docker_logs(container)
    command = 'docker inspect proxy'
    subprocess.run(command, shell=True)
    wait_for_faucet()
    run_uniswap_test()


def dump_docker_logs(container):
    try:
        # print(docker_client.containers())
        logs = docker_client.logs(container).decode("utf-8")
        with open(f"{container}.log", "w") as file:
            file.write(logs)
    except(docker.errors.NotFound):
        click.echo(f"Container {container} does not exist")


def cleanup_docker():
    click.echo(f"Cleanup docker-compose...")
    command = "docker-compose -f proxy/docker-compose-test.yml down -t 1"
    subprocess.run(command, shell=True)
    click.echo(f"Cleanup docker-compose done.")
    click.echo(f"Removing temporary data volumes...")
    command = "docker volume prune -f"
    subprocess.run(command, shell=True)
    click.echo(f"Removing temporary data done.")


def get_fauset_url():
    command = 'docker exec proxy bash -c "echo ${FAUCET_URL}"'
    out = subprocess.run(
        command, shell=True,  capture_output=True, text=True)
    print(out)
    faucet_url = out.stdout.strip()
    click.echo(f"Faucet url: {faucet_url}")
    return faucet_url


def wait_for_faucet():
    faucet_url = get_fauset_url()
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
    fauset_url = get_fauset_url()
    os.environ["FAUCET_URL"] = fauset_url

    docker_client.pull(UNISWAP_V2_CORE_IMAGE)
    command = f'docker run --rm --network=container:proxy -e FAUCET_URL --entrypoint ./deploy-test.sh {UNISWAP_V2_CORE_IMAGE} all'
    out = subprocess.run(command, shell=True)


if __name__ == "__main__":
    cli()
