terraform {
  required_providers {
    certkit = {
      source = "sensiblebit/certkit"
    }
  }
}

provider "certkit" {}

# Resolve a certificate chain with custom roots (offline/airgapped)
data "certkit_certificate" "internal" {
  leaf_pem   = file("${path.module}/certs/leaf.pem")
  fetch_aia  = false
  trust_store = "custom"

  extra_intermediates_pem = [file("${path.module}/certs/intermediate.pem")]
  custom_roots_pem        = [file("${path.module}/certs/root.pem")]
}

output "fullchain" {
  value = data.certkit_certificate.internal.fullchain_pem
}

output "leaf_skid" {
  value = data.certkit_certificate.internal.skid
}

output "leaf_akid" {
  value = data.certkit_certificate.internal.akid
}

output "intermediates" {
  value = data.certkit_certificate.internal.intermediates
}

output "roots" {
  value = data.certkit_certificate.internal.roots
}
