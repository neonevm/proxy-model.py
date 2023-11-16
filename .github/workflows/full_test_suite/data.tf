data "hcloud_image" "ci-image" {
  name              = "ubuntu-22.04"
  with_architecture = "x86"
}

data "hcloud_network" "ci-network" {
  name = "ci-network"
}

data "hcloud_ssh_key" "ci-ssh-key" {
  name = "hcloud-ci-stands"
}

variable "branch" {
  type = string
}


variable "proxy_model_commit" {
  type = string
}


variable "neon_evm_commit" {
  type = string
}


variable "faucet_model_commit" {
  type = string
}

data "template_file" "solana_init" {
  template = file("solana_init.sh")

  vars = {
    branch              = "${var.branch}"
    proxy_model_commit  = "${var.proxy_model_commit}"
    neon_evm_commit     = "${var.neon_evm_commit}"
    faucet_model_commit = "${var.faucet_model_commit}"
  }
}

data "template_file" "proxy_init" {
  template = file("proxy_init.sh")

  vars = {
    branch              = "${var.branch}"
    proxy_model_commit  = "${var.proxy_model_commit}"
    solana_ip           = hcloud_server.solana.network.*.ip[0]
    neon_evm_commit     = "${var.neon_evm_commit}"
    faucet_model_commit = "${var.faucet_model_commit}"
    ci_pp_solana_url    = "${var.ci_pp_solana_url}"
  }
}
