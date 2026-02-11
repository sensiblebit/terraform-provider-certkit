# Template: Custom roots (offline/airgapped)
#
# To use this example, place your PEM files in a certs/ subdirectory:
#   certs/leaf.pem         - leaf certificate
#   certs/intermediate.pem - intermediate CA certificate
#   certs/root.pem         - root CA certificate

terraform {
  required_providers {
    certkit = {
      source = "sensiblebit/certkit"
    }
  }
}

provider "certkit" {}

data "certkit_certificate" "internal" {
  leaf_pem    = file("${path.module}/certs/leaf.pem")
  fetch_aia   = false
  trust_store = "custom"

  extra_intermediates_pem = [file("${path.module}/certs/intermediate.pem")]
  custom_roots_pem        = [file("${path.module}/certs/root.pem")]
}

output "fullchain" {
  value = data.certkit_certificate.internal.fullchain_pem
}

output "leaf_ski" {
  value = data.certkit_certificate.internal.ski
}

output "leaf_aki" {
  value = data.certkit_certificate.internal.aki
}

output "intermediates" {
  value = data.certkit_certificate.internal.intermediates
}

output "roots" {
  value = data.certkit_certificate.internal.roots
}
