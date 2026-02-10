package provider

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestPKCS7Resource(t *testing.T) {
	ctx := context.Background()
	r := NewPKCS7Resource()

	metaResp := &resource.MetadataResponse{}
	r.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "certkit"}, metaResp)
	if metaResp.TypeName != "certkit_pkcs7" {
		t.Errorf("got type=%q", metaResp.TypeName)
	}

	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
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

func TestAccPKCS7Resource(t *testing.T) {
	caPEM, intermediatePEM, leafPEM := generateTestPKI(t)

	config := fmt.Sprintf(`
provider "certkit" {}

resource "certkit_pkcs7" "test" {
  cert_pem     = <<-EOT
%sEOT
  ca_certs_pem = [<<-EOT
%sEOT
,
    <<-EOT
%sEOT
  ]
}
`, leafPEM, intermediatePEM, caPEM)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: config,
			Check: tfresource.ComposeAggregateTestCheckFunc(
				tfresource.TestCheckResourceAttrSet("certkit_pkcs7.test", "content"),
				tfresource.TestCheckResourceAttrSet("certkit_pkcs7.test", "id"),
			),
		}},
	})
}

func TestAccPKCS7Resource_caCertsOnly(t *testing.T) {
	caPEM, intermediatePEM, _ := generateTestPKI(t)

	config := fmt.Sprintf(`
provider "certkit" {}

resource "certkit_pkcs7" "test" {
  ca_certs_pem = [
    <<-EOT
%sEOT
,
    <<-EOT
%sEOT
  ]
}
`, intermediatePEM, caPEM)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: config,
			Check: tfresource.ComposeAggregateTestCheckFunc(
				tfresource.TestCheckResourceAttrSet("certkit_pkcs7.test", "content"),
			),
		}},
	})
}

// Suppress unused import warnings
var _ = fmt.Sprintf
