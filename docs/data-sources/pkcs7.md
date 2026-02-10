---
page_title: "certkit_pkcs7 Data Source - certkit"
description: |-
  Decodes a PKCS#7/P7B bundle and exposes the certificates it contains.
---

# certkit_pkcs7 (Data Source)

Decodes a base64-encoded PKCS#7/P7B bundle and exposes the certificates it contains, with PEM encoding, subject common name, and SHA-256 fingerprint for each.

## Example Usage

### Decode a PKCS#7 bundle

```hcl
resource "certkit_pkcs7" "bundle" {
  cert_pem     = file("certs/leaf.pem")
  ca_certs_pem = [file("certs/intermediate.pem"), file("certs/root.pem")]
}

data "certkit_pkcs7" "decoded" {
  content = certkit_pkcs7.bundle.content
}

output "cert_count" {
  value = length(data.certkit_pkcs7.decoded.certificates)
}

output "first_cert_cn" {
  value = data.certkit_pkcs7.decoded.certificates[0].subject_common_name
}
```

## Schema

### Required

- `content` (String) - Base64-encoded PKCS#7/P7B bundle to decode.

### Read-Only

- `id` (String) - Computed identifier.
- `certificates` (List of Object) - Certificates extracted from the PKCS#7 bundle. Each object contains:
  - `cert_pem` (String) - PEM-encoded certificate.
  - `subject_common_name` (String) - Common Name (CN) from the certificate subject.
  - `sha256_fingerprint` (String) - SHA-256 fingerprint of the certificate.
