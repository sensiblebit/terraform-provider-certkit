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

# Encode leaf + intermediates into a PKCS#7 bundle (resource)
resource "certkit_pkcs7" "bundle" {
  cert_pem     = data.certkit_certificate.app.cert_pem
  ca_certs_pem = [for i in data.certkit_certificate.app.intermediates : i.cert_pem]
}

# Decode the PKCS#7 bundle (data source)
data "certkit_pkcs7" "decoded" {
  content = certkit_pkcs7.bundle.content
}

output "p7b_base64" {
  value = certkit_pkcs7.bundle.content
}

output "decoded_cert_count" {
  value = length(data.certkit_pkcs7.decoded.certificates)
}

output "decoded_first_cn" {
  value = data.certkit_pkcs7.decoded.certificates[0].subject_common_name
}
