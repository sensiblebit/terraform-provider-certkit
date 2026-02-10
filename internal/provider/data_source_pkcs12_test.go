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

	required := []string{"content"}
	optional := []string{"password"}
	computed := []string{"cert_pem", "private_key_pem", "ca_certs_pem", "key_algorithm", "id"}
	for _, attr := range slices.Concat(required, optional, computed) {
		if _, ok := schemaResp.Schema.Attributes[attr]; !ok {
			t.Errorf("missing attribute %q", attr)
		}
	}
}

// TestAccPKCS12DataSource_roundTrip encodes with the resource, decodes with the data source.
func TestAccPKCS12DataSource_roundTrip(t *testing.T) {
	_, intermediatePEM, leafPEM, leafKeyPEM := generateTestPKIWithKey(t)

	config := fmt.Sprintf(`
provider "certkit" {}

resource "certkit_pkcs12" "encode" {
  cert_pem        = <<-EOT
%sEOT
  private_key_pem = <<-EOT
%sEOT
  ca_certs_pem    = [<<-EOT
%sEOT
  ]
  password        = "test-password"
}

data "certkit_pkcs12" "decode" {
  content  = certkit_pkcs12.encode.content
  password = "test-password"
}
`, leafPEM, leafKeyPEM, intermediatePEM)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.certkit_pkcs12.decode", "cert_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_pkcs12.decode", "private_key_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_pkcs12.decode", "key_algorithm"),
				resource.TestCheckResourceAttrSet("data.certkit_pkcs12.decode", "id"),
				resource.TestCheckResourceAttr("data.certkit_pkcs12.decode", "key_algorithm", "ECDSA"),
				resource.TestCheckResourceAttr("data.certkit_pkcs12.decode", "ca_certs_pem.#", "1"),
			),
		}},
	})
}
