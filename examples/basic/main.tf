terraform {
  required_providers {
    certkit = {
      source = "sensiblebit/certkit"
    }
  }
}

provider "certkit" {}

# Fetch leaf from google.com via TLS, resolve chain via AIA + system trust
data "certkit_certificate" "app" {
  url         = "https://google.com"
  fetch_aia   = true
  trust_store = "system"
}

output "fullchain" {
  value = data.certkit_certificate.app.fullchain_pem
}

output "leaf_fingerprint" {
  value = data.certkit_certificate.app.sha256_fingerprint
}

# SHA-256 computed (RFC 7093, always consistent across mixed chains)
output "leaf_skid" {
  value = data.certkit_certificate.app.skid
}

output "leaf_akid" {
  value = data.certkit_certificate.app.akid
}

# Structured intermediate/root data
output "intermediates" {
  value = data.certkit_certificate.app.intermediates
}

output "roots" {
  value = data.certkit_certificate.app.roots
}

output "intermediate_skid" {
  value = data.certkit_certificate.app.intermediates[0].skid
}

output "root_skid" {
  value = data.certkit_certificate.app.roots[0].skid
}

output "warnings" {
  value = data.certkit_certificate.app.warnings
}

# Generate a CSR from the resolved certificate (resource)
resource "certkit_cert_request" "app" {
  cert_pem = data.certkit_certificate.app.cert_pem
}

output "csr_pem" {
  value = certkit_cert_request.app.cert_request_pem
}

# Encode a PKCS#7 bundle (resource)
resource "certkit_pkcs7" "app" {
  cert_pem     = data.certkit_certificate.app.cert_pem
  ca_certs_pem = [for i in data.certkit_certificate.app.intermediates : i.cert_pem]
}

output "p7b_content" {
  value = certkit_pkcs7.app.content
}

# Decode the PKCS#7 bundle (data source)
data "certkit_pkcs7" "decoded" {
  content = certkit_pkcs7.app.content
}

output "p7b_cert_count" {
  value = length(data.certkit_pkcs7.decoded.certificates)
}
