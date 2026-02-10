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

# Generate a CSR with an auto-generated key (stored in state)
resource "certkit_cert_request" "renewal" {
  cert_pem = data.certkit_certificate.app.cert_pem
}

# Inspect the CSR
data "certkit_cert_request" "inspect" {
  cert_request_pem = certkit_cert_request.renewal.cert_request_pem
}

output "csr_pem" {
  value = certkit_cert_request.renewal.cert_request_pem
}

output "key_algorithm" {
  value = certkit_cert_request.renewal.key_algorithm
}

output "private_key" {
  value     = certkit_cert_request.renewal.private_key_pem
  sensitive = true
}

output "subject_common_name" {
  value = data.certkit_cert_request.inspect.subject_common_name
}

output "dns_names" {
  value = data.certkit_cert_request.inspect.dns_names
}

output "signature_algorithm" {
  value = data.certkit_cert_request.inspect.signature_algorithm
}
