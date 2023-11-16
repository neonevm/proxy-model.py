output "solana_ip" {
  value = hcloud_server.solana.ipv4_address
}

output "proxy_ip" {
  value = hcloud_server.proxy.ipv4_address
}

output "branch" {
  value = var.branch
}
