---
page_title: "certkit_pkcs7 Resource - certkit"
description: |-
  Encodes certificates into a PKCS#7/P7B bundle (certs only, no private key).
---

# certkit_pkcs7 (Resource)

Encodes certificates into a certs-only PKCS#7/P7B bundle (degenerate SignedData structure with no signatures). The output is base64-encoded and stored in state. Changing any input forces replacement of the resource.

No private key is included or required.

## Example Usage

### Basic

```hcl
data "certkit_certificate" "app" {
  url         = "https://example.com"
  trust_store = "mozilla"
}

resource "certkit_pkcs7" "bundle" {
  cert_pem     = data.certkit_certificate.app.cert_pem
  ca_certs_pem = [for i in data.certkit_certificate.app.intermediates : i.cert_pem]
}

output "p7b_base64" {
  value = certkit_pkcs7.bundle.content
}
```

### CA certificates only

```hcl
resource "certkit_pkcs7" "ca_bundle" {
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

- `cert_pem` (String) - PEM-encoded primary certificate to include. Changing forces replacement.
- `ca_certs_pem` (List of String) - PEM-encoded CA certificates to include in the bundle. Changing forces replacement.

### Read-Only

- `id` (String) - Computed identifier.
- `content` (String) - Base64-encoded PKCS#7/P7B bundle.
