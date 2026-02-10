package provider

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestPKCS7DataSource(t *testing.T) {
	ctx := context.Background()
	ds := NewPKCS7DataSource()

	metaResp := &datasource.MetadataResponse{}
	ds.Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "certkit"}, metaResp)
	if metaResp.TypeName != "certkit_pkcs7" {
		t.Errorf("got type=%q", metaResp.TypeName)
	}

	schemaResp := &datasource.SchemaResponse{}
	ds.Schema(ctx, datasource.SchemaRequest{}, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatal(schemaResp.Diagnostics)
	}

	optional := []string{"cert_pem", "ca_certs_pem"}
	computed := []string{"content", "id"}
	for _, attr := range slices.Concat(optional, computed) {
		if _, ok := schemaResp.Schema.Attributes[attr]; !ok {
			t.Errorf("missing attribute %q", attr)
		}
	}
}

// TestAccPKCS7DataSource tests PKCS#7 encoding composing with certkit_certificate.
func TestAccPKCS7DataSource(t *testing.T) {
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

data "certkit_pkcs7" "test" {
  cert_pem     = data.certkit_certificate.test.cert_pem
  ca_certs_pem = [for i in data.certkit_certificate.test.intermediates : i.cert_pem]
}
`, leafPEM, intermediatePEM, caPEM)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.certkit_pkcs7.test", "content"),
				resource.TestCheckResourceAttrSet("data.certkit_pkcs7.test", "id"),
			),
		}},
	})
}

// TestAccPKCS7DataSource_caCertsOnly tests PKCS#7 with only ca_certs_pem (no cert_pem).
func TestAccPKCS7DataSource_caCertsOnly(t *testing.T) {
	caPEM, intermediatePEM, _ := generateTestPKI(t)

	config := fmt.Sprintf(`
provider "certkit" {}

data "certkit_pkcs7" "test" {
  ca_certs_pem = [
    <<-EOT
%sEOT
,
    <<-EOT
%sEOT
  ]
}
`, intermediatePEM, caPEM)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.certkit_pkcs7.test", "content"),
			),
		}},
	})
}
