---
page_title: "certkit_pkcs7 Data Source - certkit"
description: |-
  Encodes certificates into a PKCS#7/P7B bundle (certs only, no private key).
---

# certkit_pkcs7 (Data Source)

Encodes certificates into a certs-only PKCS#7/P7B bundle (degenerate SignedData structure with no signatures). The output is base64-encoded and can be written to a file or passed to resources that accept P7B input.

No private key is included or required.

## Example Usage

### Basic

```hcl
data "certkit_certificate" "app" {
  url         = "https://example.com"
  trust_store = "mozilla"
}

data "certkit_pkcs7" "bundle" {
  cert_pem     = data.certkit_certificate.app.cert_pem
  ca_certs_pem = [for i in data.certkit_certificate.app.intermediates : i.cert_pem]
}

output "p7b_base64" {
  value = data.certkit_pkcs7.bundle.content
}
```

### CA certificates only

```hcl
data "certkit_pkcs7" "ca_bundle" {
  ca_certs_pem = [
    file("certs/intermediate.pem"),
    file("certs/root.pem"),
  ]
}
```

## Schema

### Required

At least one of `cert_pem` or `ca_certs_pem` must be set.

### Optional

- `cert_pem` (String) - PEM-encoded primary certificate to include.
- `ca_certs_pem` (List of String) - PEM-encoded CA certificates to include in the bundle.

### Read-Only

- `id` (String) - Computed identifier.
- `content` (String) - Base64-encoded PKCS#7/P7B bundle.
