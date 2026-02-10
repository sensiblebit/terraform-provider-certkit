package provider

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestPKCS12DataSource(t *testing.T) {
	ctx := context.Background()
	ds := NewPKCS12DataSource()

	metaResp := &datasource.MetadataResponse{}
	ds.Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "certkit"}, metaResp)
	if metaResp.TypeName != "certkit_pkcs12" {
		t.Errorf("got type=%q", metaResp.TypeName)
	}

	schemaResp := &datasource.SchemaResponse{}
	ds.Schema(ctx, datasource.SchemaRequest{}, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatal(schemaResp.Diagnostics)
	}

	required := []string{"cert_pem", "private_key_pem"}
	optional := []string{"ca_certs_pem", "password"}
	computed := []string{"content", "id"}
	for _, attr := range slices.Concat(required, optional, computed) {
		if _, ok := schemaResp.Schema.Attributes[attr]; !ok {
			t.Errorf("missing attribute %q", attr)
		}
	}
}

// TestAccPKCS12DataSource tests PKCS#12 encoding composing with certkit_certificate.
func TestAccPKCS12DataSource(t *testing.T) {
	caPEM, intermediatePEM, leafPEM, leafKeyPEM := generateTestPKIWithKey(t)

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

data "certkit_pkcs12" "test" {
  cert_pem        = data.certkit_certificate.test.cert_pem
  ca_certs_pem    = [for i in data.certkit_certificate.test.intermediates : i.cert_pem]
  private_key_pem = <<-EOT
%sEOT
  password        = "test-password"
}
`, leafPEM, intermediatePEM, caPEM, leafKeyPEM)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.certkit_pkcs12.test", "content"),
				resource.TestCheckResourceAttrSet("data.certkit_pkcs12.test", "id"),
			),
		}},
	})
}
