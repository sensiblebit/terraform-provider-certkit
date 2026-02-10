---
page_title: "certkit_pkcs12 Data Source - certkit"
description: |-
  Decodes a PKCS#12/PFX bundle and exposes its certificate, private key, and CA chain.
---

# certkit_pkcs12 (Data Source)

Decodes a base64-encoded PKCS#12/PFX bundle and exposes its leaf certificate, private key (in PKCS#8 PEM format), and CA certificates.

## Example Usage

### Decode a PKCS#12 bundle

```hcl
resource "certkit_pkcs12" "bundle" {
  cert_pem        = file("certs/leaf.pem")
  private_key_pem = file("certs/key.pem")
  ca_certs_pem    = [file("certs/intermediate.pem")]
  password        = "changeit"
}

data "certkit_pkcs12" "decoded" {
  content  = certkit_pkcs12.bundle.content
  password = "changeit"
}

output "leaf_cert" {
  value = data.certkit_pkcs12.decoded.cert_pem
}

output "key_algorithm" {
  value = data.certkit_pkcs12.decoded.key_algorithm
}
```

## Schema

### Required

- `content` (String, Sensitive) - Base64-encoded PKCS#12/PFX bundle to decode.

### Optional

- `password` (String, Sensitive) - Password for PKCS#12 decryption. Default: empty string.

### Read-Only

- `id` (String) - Computed identifier.
- `cert_pem` (String) - PEM-encoded leaf certificate extracted from the bundle.
- `private_key_pem` (String, Sensitive) - PEM-encoded private key extracted from the bundle (PKCS#8 format).
- `ca_certs_pem` (List of String) - PEM-encoded CA certificates extracted from the bundle.
- `key_algorithm` (String) - Algorithm of the private key: `ECDSA`, `RSA`, or `Ed25519`.
