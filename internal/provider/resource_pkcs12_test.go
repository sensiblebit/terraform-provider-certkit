package provider

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestPKCS12Resource(t *testing.T) {
	ctx := context.Background()
	r := NewPKCS12Resource()

	metaResp := &resource.MetadataResponse{}
	r.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "certkit"}, metaResp)
	if metaResp.TypeName != "certkit_pkcs12" {
		t.Errorf("got type=%q", metaResp.TypeName)
	}

	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
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

func TestAccPKCS12Resource(t *testing.T) {
	caPEM, intermediatePEM, leafPEM, leafKeyPEM := generateTestPKIWithKey(t)

	config := fmt.Sprintf(`
provider "certkit" {}

resource "certkit_pkcs12" "test" {
  cert_pem        = <<-EOT
%sEOT
  private_key_pem = <<-EOT
%sEOT
  ca_certs_pem    = [<<-EOT
%sEOT
,
    <<-EOT
%sEOT
  ]
  password        = "test-password"
}
`, leafPEM, leafKeyPEM, intermediatePEM, caPEM)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: config,
			Check: tfresource.ComposeAggregateTestCheckFunc(
				tfresource.TestCheckResourceAttrSet("certkit_pkcs12.test", "content"),
				tfresource.TestCheckResourceAttrSet("certkit_pkcs12.test", "id"),
			),
		}},
	})
}

// Suppress unused import warnings
var _ = fmt.Sprintf
