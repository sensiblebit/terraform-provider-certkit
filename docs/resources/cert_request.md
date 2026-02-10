---
page_title: "certkit_cert_request Resource - certkit"
description: |-
  Generates a Certificate Signing Request (CSR) by copying Subject and SANs from an existing certificate. Stores the private key in state.
---

# certkit_cert_request (Resource)

Generates a Certificate Signing Request (CSR) by copying the Subject, DNS SANs, IP SANs, and URI SANs from an existing certificate. The private key is stored in Terraform state, making it suitable for workflows where the CSR and key need to persist across applies.

If no private key is provided, an EC P-256 key is auto-generated and stored in state.

## Example Usage

### With existing private key

```hcl
data "certkit_certificate" "app" {
  url         = "https://example.com"
  trust_store = "mozilla"
}

resource "certkit_cert_request" "renewal" {
  cert_pem        = data.certkit_certificate.app.cert_pem
  private_key_pem = file("certs/key.pem")
}

output "csr" {
  value = certkit_cert_request.renewal.cert_request_pem
}

output "algorithm" {
  value = certkit_cert_request.renewal.key_algorithm
}
```

### Auto-generated key

```hcl
resource "certkit_cert_request" "renewal" {
  cert_pem = data.certkit_certificate.app.cert_pem
}

output "csr" {
  value = certkit_cert_request.renewal.cert_request_pem
}

output "private_key" {
  value     = certkit_cert_request.renewal.private_key_pem
  sensitive = true
}
```

## Schema

### Required

- `cert_pem` (String) - PEM-encoded certificate to copy Subject and SANs from. Changing this forces a new resource.

### Optional

- `private_key_pem` (String, Sensitive) - PEM-encoded private key for signing the CSR. Supports ECDSA, RSA, and Ed25519 keys in PKCS#1, PKCS#8, or EC formats. If omitted, an EC P-256 key is auto-generated. Changing this forces a new resource.

### Read-Only

- `id` (String) - Computed identifier.
- `cert_request_pem` (String) - PEM-encoded Certificate Signing Request.
- `key_algorithm` (String) - Algorithm of the private key: `ECDSA`, `RSA`, or `Ed25519`.
