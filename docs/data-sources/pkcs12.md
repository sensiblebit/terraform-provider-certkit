---
page_title: "certkit_pkcs12 Data Source - certkit"
description: |-
  Encodes a certificate, CA chain, and private key into a PKCS#12/PFX bundle.
---

# certkit_pkcs12 (Data Source)

Encodes a leaf certificate, optional CA chain, and private key into a PKCS#12/PFX bundle. The output is base64-encoded and can be written to a file or passed to resources that accept PFX input.

Uses modern encryption (AES-256-CBC + SHA-256 HMAC) via the `go-pkcs12` library.

## Example Usage

### Basic

```hcl
data "certkit_certificate" "app" {
  url         = "https://example.com"
  trust_store = "mozilla"
}

data "certkit_pkcs12" "bundle" {
  cert_pem        = data.certkit_certificate.app.cert_pem
  private_key_pem = file("certs/key.pem")
  ca_certs_pem    = [for i in data.certkit_certificate.app.intermediates : i.cert_pem]
  password        = "changeit"
}

output "pfx_base64" {
  value     = data.certkit_pkcs12.bundle.content
  sensitive = true
}
```

### Write to file

```hcl
resource "local_file" "pfx" {
  content_base64 = data.certkit_pkcs12.bundle.content
  filename       = "${path.module}/bundle.pfx"
}
```

## Schema

### Required

- `cert_pem` (String) - PEM-encoded leaf certificate.
- `private_key_pem` (String, Sensitive) - PEM-encoded private key for the leaf certificate. Supports ECDSA, RSA, and Ed25519.

### Optional

- `ca_certs_pem` (List of String) - PEM-encoded CA certificates to include in the bundle.
- `password` (String, Sensitive) - Password for PKCS#12 encryption. Default: empty string.

### Read-Only

- `id` (String) - Computed identifier.
- `content` (String, Sensitive) - Base64-encoded PKCS#12/PFX bundle.
