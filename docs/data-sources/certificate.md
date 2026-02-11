---
page_title: "certkit_certificate Data Source - certkit"
description: |-
  Resolves a certificate chain from a leaf certificate and verifies it against a trust store.
---

# certkit_certificate (Data Source)

Resolves a certificate chain from a leaf certificate, optionally following AIA (Authority Information Access) URLs to discover intermediates, and verifies the chain against a trust store.

The leaf certificate can be fetched via TLS handshake from a URL or provided directly as PEM.

## Example Usage

### Fetch from URL

```hcl
data "certkit_certificate" "app" {
  url         = "https://example.com"
  trust_store = "mozilla"
}

output "fullchain" {
  value = data.certkit_certificate.app.fullchain_pem
}

output "leaf_fingerprint" {
  value = data.certkit_certificate.app.sha256_fingerprint
}

output "intermediates" {
  value = data.certkit_certificate.app.intermediates
}
```

### Provide PEM directly

```hcl
data "certkit_certificate" "internal" {
  leaf_pem   = file("certs/leaf.pem")
  fetch_aia  = false
  trust_store = "custom"

  extra_intermediates_pem = [file("certs/intermediate.pem")]
  custom_roots_pem        = [file("certs/root.pem")]
}
```

### Without verification

```hcl
data "certkit_certificate" "unverified" {
  leaf_pem = file("certs/leaf.pem")
  verify   = false

  extra_intermediates_pem = [file("certs/intermediate.pem")]
}
```

## Schema

### Required

Exactly one of `url` or `leaf_pem` must be set.

- `url` (String) - HTTPS URL to fetch the leaf certificate from via TLS handshake (e.g., `https://example.com`). Mutually exclusive with `leaf_pem`.
- `leaf_pem` (String) - PEM-encoded leaf certificate. Mutually exclusive with `url`.

### Optional

- `extra_intermediates_pem` (List of String) - Additional PEM-encoded intermediate certificates to aid chain building.
- `fetch_aia` (Boolean) - Fetch intermediate certificates via AIA URLs. Default: `true`.
- `aia_timeout_ms` (Number) - Timeout in milliseconds for each AIA HTTP fetch. Default: `2000`.
- `aia_max_depth` (Number) - Maximum number of AIA fetches to follow. Default: `5`.
- `trust_store` (String) - Trust store for verification: `system`, `mozilla`, or `custom`. Default: `system`.
- `custom_roots_pem` (List of String) - PEM-encoded root certificates. Required when `trust_store = "custom"`.
- `verify` (Boolean) - Verify the certificate chain against the trust store. Default: `true`.
- `colon_separated` (Boolean) - Use colon-separated hex for fingerprints and identifiers (e.g., `ab:cd:ef`). When `false`, outputs plain hex. Default: `true`.

### Read-Only

- `id` (String) - Computed identifier.
- `cert_pem` (String) - Leaf certificate in PEM format (normalized).
- `chain_pem` (String) - Concatenated PEM: leaf + intermediates.
- `fullchain_pem` (String) - Concatenated PEM: leaf + intermediates + root.
- `sha256_fingerprint` (String) - SHA-256 fingerprint of the leaf certificate.
- `ski` (String) - Leaf Subject Key Identifier (RFC 7093 Method 1: truncated SHA-256 of public key).
- `ski_embedded` (String) - Leaf Subject Key Identifier from the certificate extension (may be SHA-1 or SHA-256).
- `aki` (String) - Leaf Authority Key Identifier (RFC 7093 SKI of the issuer).
- `aki_embedded` (String) - Leaf Authority Key Identifier from the certificate extension.
- `intermediates` (List of Object) - Intermediate certificates with metadata. Each object contains: `cert_pem`, `sha256_fingerprint`, `ski`, `ski_embedded`, `aki`, `aki_embedded`.
- `roots` (List of Object) - Root certificates with the same attributes as intermediates.
- `warnings` (List of String) - Non-fatal warnings (e.g., AIA fetch failures).

## SKI Calculation

The `ski` attribute is computed using RFC 7093 Section 2 Method 1: the leftmost 160 bits of the SHA-256 hash of the public key BIT STRING. This produces a consistent 20-byte identifier for any given key, regardless of what the issuing CA embeds in the certificate extension.

The `ski_embedded` attribute returns whatever value the CA placed in the Subject Key Identifier extension, which is typically SHA-1 but may differ.
