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

	required := []string{"content"}
	computed := []string{"certificates", "id"}
	for _, attr := range slices.Concat(required, computed) {
		if _, ok := schemaResp.Schema.Attributes[attr]; !ok {
			t.Errorf("missing attribute %q", attr)
		}
	}
}

// TestAccPKCS7DataSource_roundTrip encodes with the resource, decodes with the data source.
func TestAccPKCS7DataSource_roundTrip(t *testing.T) {
	caPEM, intermediatePEM, leafPEM := generateTestPKI(t)

	config := fmt.Sprintf(`
provider "certkit" {}

resource "certkit_pkcs7" "encode" {
  cert_pem     = <<-EOT
%sEOT
  ca_certs_pem = [<<-EOT
%sEOT
,
    <<-EOT
%sEOT
  ]
}

data "certkit_pkcs7" "decode" {
  content = certkit_pkcs7.encode.content
}
`, leafPEM, intermediatePEM, caPEM)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.certkit_pkcs7.decode", "id"),
				resource.TestCheckResourceAttr("data.certkit_pkcs7.decode", "certificates.#", "3"),
				resource.TestCheckResourceAttrSet("data.certkit_pkcs7.decode", "certificates.0.cert_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_pkcs7.decode", "certificates.0.subject_common_name"),
				resource.TestCheckResourceAttrSet("data.certkit_pkcs7.decode", "certificates.0.sha256_fingerprint"),
			),
		}},
	})
}
