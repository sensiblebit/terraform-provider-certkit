terraform {
  required_providers {
    certkit = {
      source = "sensiblebit/certkit"
    }
  }
}

provider "certkit" {}

# Resolve the certificate chain
data "certkit_certificate" "app" {
  url         = "https://google.com"
  trust_store = "mozilla"
}

# Generate a CSR with an auto-generated key
data "certkit_cert_request" "renewal" {
  cert_pem = data.certkit_certificate.app.cert_pem
}

output "csr_pem" {
  value = data.certkit_cert_request.renewal.cert_request_pem
}

output "key_algorithm" {
  value = data.certkit_cert_request.renewal.key_algorithm
}

output "private_key" {
  value     = data.certkit_cert_request.renewal.private_key_pem
  sensitive = true
}
