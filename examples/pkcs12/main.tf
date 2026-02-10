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
data "certkit_cert_request" "app" {
  cert_pem = data.certkit_certificate.app.cert_pem
}

# Encode into a PKCS#12 bundle
data "certkit_pkcs12" "bundle" {
  cert_pem        = data.certkit_certificate.app.cert_pem
  private_key_pem = data.certkit_cert_request.app.private_key_pem
  ca_certs_pem    = [for i in data.certkit_certificate.app.intermediates : i.cert_pem]
  password        = "changeit"
}

output "pfx_base64" {
  value     = data.certkit_pkcs12.bundle.content
  sensitive = true
}
