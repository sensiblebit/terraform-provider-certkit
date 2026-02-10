---
page_title: "certkit_cert_request Data Source - certkit"
description: |-
  Generates a Certificate Signing Request (CSR) by copying Subject and SANs from an existing certificate.
---

# certkit_cert_request (Data Source)

Generates a Certificate Signing Request (CSR) by copying the Subject, DNS SANs, IP SANs, and URI SANs from an existing certificate. Useful for certificate renewal workflows where you need a CSR that matches the current certificate.

If no private key is provided, an EC P-256 key is auto-generated (changes every apply).

## Example Usage

### With existing private key

```hcl
data "certkit_certificate" "app" {
  url         = "https://example.com"
  trust_store = "mozilla"
}

data "certkit_cert_request" "renewal" {
  cert_pem        = data.certkit_certificate.app.cert_pem
  private_key_pem = file("certs/key.pem")
}

output "csr" {
  value = data.certkit_cert_request.renewal.cert_request_pem
}

output "algorithm" {
  value = data.certkit_cert_request.renewal.key_algorithm
}
```

### Auto-generated key

```hcl
data "certkit_cert_request" "renewal" {
  cert_pem = data.certkit_certificate.app.cert_pem
}

output "csr" {
  value = data.certkit_cert_request.renewal.cert_request_pem
}

output "private_key" {
  value     = data.certkit_cert_request.renewal.private_key_pem
  sensitive = true
}
```

## Schema

### Required

- `cert_pem` (String) - PEM-encoded certificate to copy Subject and SANs from.

### Optional

- `private_key_pem` (String, Sensitive) - PEM-encoded private key for signing the CSR. Supports ECDSA, RSA, and Ed25519 keys in PKCS#1, PKCS#8, or EC formats. If omitted, an EC P-256 key is auto-generated.

### Read-Only

- `id` (String) - Computed identifier.
- `cert_request_pem` (String) - PEM-encoded Certificate Signing Request.
- `private_key_pem` (String, Sensitive) - Private key used to sign the CSR (passthrough if provided, auto-generated if not).
- `key_algorithm` (String) - Algorithm of the private key: `ECDSA`, `RSA`, or `Ed25519`.
