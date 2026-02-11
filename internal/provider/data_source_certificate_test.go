package provider

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCertificateDataSource(t *testing.T) {
	ctx := context.Background()
	ds := NewCertificateDataSource()

	// Metadata
	metaResp := &datasource.MetadataResponse{}
	ds.Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "certkit"}, metaResp)
	if metaResp.TypeName != "certkit_certificate" {
		t.Errorf("got type=%q", metaResp.TypeName)
	}

	// Schema
	schemaResp := &datasource.SchemaResponse{}
	ds.Schema(ctx, datasource.SchemaRequest{}, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatal(schemaResp.Diagnostics)
	}

	optional := []string{
		"url", "leaf_pem",
		"extra_intermediates_pem", "fetch_aia",
		"aia_timeout_ms", "aia_max_depth", "trust_store", "custom_roots_pem",
		"verify", "include_root", "colon_separated",
	}
	computed := []string{
		"id", "cert_pem", "chain_pem", "fullchain_pem",
		"sha256_fingerprint", "skid", "skid_embedded", "akid", "akid_embedded",
		"intermediates", "roots", "warnings",
	}
	for _, attr := range slices.Concat(optional, computed) {
		if _, ok := schemaResp.Schema.Attributes[attr]; !ok {
			t.Errorf("missing attribute %q", attr)
		}
	}
}

// TestAccCertificateDataSource_customPKI tests with a self-signed CA chain (no network needed).
func TestAccCertificateDataSource_customPKI(t *testing.T) {
	caPEM, intermediatePEM, leafPEM := generateTestPKI(t)

	config := fmt.Sprintf(`
provider "certkit" {}

data "certkit_certificate" "test" {
  leaf_pem = <<-EOT
%sEOT

  extra_intermediates_pem = [<<-EOT
%sEOT
  ]

  fetch_aia   = false
  trust_store = "custom"
  custom_roots_pem = [<<-EOT
%sEOT
  ]
}
`, leafPEM, intermediatePEM, caPEM)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "cert_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "chain_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "fullchain_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "sha256_fingerprint"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "skid"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "akid"),
				resource.TestCheckResourceAttr("data.certkit_certificate.test", "intermediates.#", "1"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "intermediates.0.cert_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "intermediates.0.sha256_fingerprint"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "intermediates.0.skid"),
				resource.TestCheckResourceAttr("data.certkit_certificate.test", "roots.#", "1"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "roots.0.cert_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "roots.0.sha256_fingerprint"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "roots.0.skid"),
			),
		}},
	})
}

// TestAccCertificateDataSource_customWithoutRoots tests validation error when trust_store=custom without custom_roots_pem.
func TestAccCertificateDataSource_customWithoutRoots(t *testing.T) {
	_, _, leafPEM := generateTestPKI(t)

	config := fmt.Sprintf(`
provider "certkit" {}

data "certkit_certificate" "test" {
  leaf_pem    = <<-EOT
%sEOT

  fetch_aia   = false
  trust_store = "custom"
}
`, leafPEM)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      config,
			ExpectError: regexp.MustCompile(`custom_roots_pem must be set when trust_store is "custom"`),
		}},
	})
}

// TestAccCertificateDataSource_invalidTrustStore tests validation error for unknown trust_store values.
func TestAccCertificateDataSource_invalidTrustStore(t *testing.T) {
	_, _, leafPEM := generateTestPKI(t)

	config := fmt.Sprintf(`
provider "certkit" {}

data "certkit_certificate" "test" {
  leaf_pem    = <<-EOT
%sEOT

  fetch_aia   = false
  trust_store = "invalid"
}
`, leafPEM)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      config,
			ExpectError: regexp.MustCompile(`trust_store must be "system", "mozilla", or "custom"`),
		}},
	})
}

// TestAccCertificateDataSource_verifyFalse tests that verify=false passes through intermediates without chain verification.
func TestAccCertificateDataSource_verifyFalse(t *testing.T) {
	_, intermediatePEM, leafPEM := generateTestPKI(t)

	config := fmt.Sprintf(`
provider "certkit" {}

data "certkit_certificate" "test" {
  leaf_pem = <<-EOT
%sEOT

  extra_intermediates_pem = [<<-EOT
%sEOT
  ]

  fetch_aia = false
  verify    = false
}
`, leafPEM, intermediatePEM)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "cert_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "chain_pem"),
				// Intermediates passed through without verification
				resource.TestCheckResourceAttr("data.certkit_certificate.test", "intermediates.#", "1"),
				// No roots when verify=false (no chain verification to discover root)
				resource.TestCheckResourceAttr("data.certkit_certificate.test", "roots.#", "0"),
			),
		}},
	})
}

// TestAccCertificateDataSource_aiaNoUrls tests graceful handling when leaf has no AIA URLs.
func TestAccCertificateDataSource_aiaNoUrls(t *testing.T) {
	caPEM, intermediatePEM, leafPEM := generateTestPKI(t)

	// Our test PKI leaf has no AIA URLs, so fetch_aia=true should just proceed with no extra fetches
	config := fmt.Sprintf(`
provider "certkit" {}

data "certkit_certificate" "test" {
  leaf_pem = <<-EOT
%sEOT

  extra_intermediates_pem = [<<-EOT
%sEOT
  ]

  fetch_aia      = true
  aia_timeout_ms = 1
  trust_store    = "custom"
  custom_roots_pem = [<<-EOT
%sEOT
  ]
}
`, leafPEM, intermediatePEM, caPEM)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "cert_pem"),
				resource.TestCheckResourceAttr("data.certkit_certificate.test", "intermediates.#", "1"),
				resource.TestCheckResourceAttr("data.certkit_certificate.test", "roots.#", "1"),
			),
		}},
	})
}

// TestAccCertificateDataSource_mozillaRoots tests trust_store=mozilla with embedded Mozilla root certificates.
func TestAccCertificateDataSource_mozillaRoots(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
provider "certkit" {}

data "certkit_certificate" "test" {
  url         = "https://google.com"
  fetch_aia   = true
  trust_store = "mozilla"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "cert_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "chain_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.test", "fullchain_pem"),
				resource.TestCheckResourceAttr("data.certkit_certificate.test", "intermediates.#", "1"),
				resource.TestCheckResourceAttr("data.certkit_certificate.test", "roots.#", "1"),
			),
		}},
	})
}

// TestAccCertificateDataSource_googleURL tests the url input with live google.com.
func TestAccCertificateDataSource_googleURL(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
provider "certkit" {}

data "certkit_certificate" "google" {
  url         = "https://google.com"
  fetch_aia   = true
  trust_store = "system"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.certkit_certificate.google", "cert_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.google", "chain_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.google", "fullchain_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.google", "sha256_fingerprint"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.google", "skid"),
				resource.TestCheckResourceAttr("data.certkit_certificate.google", "intermediates.#", "1"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.google", "intermediates.0.cert_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.google", "intermediates.0.skid"),
				resource.TestCheckResourceAttr("data.certkit_certificate.google", "roots.#", "1"),
				resource.TestCheckResourceAttrSet("data.certkit_certificate.google", "roots.0.cert_pem"),
			),
		}},
	})
}
