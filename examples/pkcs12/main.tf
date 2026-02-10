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

# Generate a CSR + key pair (for demo purposes)
resource "certkit_cert_request" "app" {
  cert_pem = data.certkit_certificate.app.cert_pem
}

# Encode into a PKCS#12 bundle (resource)
resource "certkit_pkcs12" "bundle" {
  cert_pem        = data.certkit_certificate.app.cert_pem
  private_key_pem = certkit_cert_request.app.private_key_pem
  ca_certs_pem    = [for i in data.certkit_certificate.app.intermediates : i.cert_pem]
  password        = "changeit"
}

# Decode the PKCS#12 bundle (data source)
data "certkit_pkcs12" "decoded" {
  content  = certkit_pkcs12.bundle.content
  password = "changeit"
}

output "pfx_base64" {
  value     = certkit_pkcs12.bundle.content
  sensitive = true
}

output "decoded_key_algorithm" {
  value = data.certkit_pkcs12.decoded.key_algorithm
}

output "decoded_ca_count" {
  value = length(data.certkit_pkcs12.decoded.ca_certs_pem)
}
