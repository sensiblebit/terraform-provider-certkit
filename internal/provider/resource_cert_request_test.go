package provider

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCertRequestResource(t *testing.T) {
	ctx := context.Background()
	r := NewCertRequestResource()

	metaResp := &resource.MetadataResponse{}
	r.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "certkit"}, metaResp)
	if metaResp.TypeName != "certkit_cert_request" {
		t.Errorf("got type=%q", metaResp.TypeName)
	}

	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatal(schemaResp.Diagnostics)
	}

	required := []string{"cert_pem"}
	optionalComputed := []string{"private_key_pem"}
	computed := []string{"cert_request_pem", "key_algorithm", "id"}
	for _, attr := range slices.Concat(required, optionalComputed, computed) {
		if _, ok := schemaResp.Schema.Attributes[attr]; !ok {
			t.Errorf("missing attribute %q", attr)
		}
	}
}

// TestAccCertRequestResource_withKey tests resource creation with a provided private key.
func TestAccCertRequestResource_withKey(t *testing.T) {
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

resource "certkit_cert_request" "test" {
  cert_pem        = data.certkit_certificate.test.cert_pem
  private_key_pem = <<-EOT
%sEOT
}
`, leafPEM, intermediatePEM, caPEM, leafKeyPEM)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: config,
			Check: tfresource.ComposeAggregateTestCheckFunc(
				tfresource.TestCheckResourceAttrSet("certkit_cert_request.test", "cert_request_pem"),
				tfresource.TestCheckResourceAttrSet("certkit_cert_request.test", "private_key_pem"),
				tfresource.TestCheckResourceAttr("certkit_cert_request.test", "key_algorithm", "ECDSA"),
				tfresource.TestCheckResourceAttrSet("certkit_cert_request.test", "id"),
			),
		}},
	})
}

// TestAccCertRequestResource_autoGen tests resource creation with auto-generated key.
func TestAccCertRequestResource_autoGen(t *testing.T) {
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

resource "certkit_cert_request" "test" {
  cert_pem = data.certkit_certificate.test.cert_pem
}
`, leafPEM, intermediatePEM, caPEM)

	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{
			{
				Config: config,
				Check: tfresource.ComposeAggregateTestCheckFunc(
					tfresource.TestCheckResourceAttrSet("certkit_cert_request.test", "cert_request_pem"),
					tfresource.TestCheckResourceAttrSet("certkit_cert_request.test", "private_key_pem"),
					tfresource.TestCheckResourceAttr("certkit_cert_request.test", "key_algorithm", "ECDSA"),
					tfresource.TestCheckResourceAttrSet("certkit_cert_request.test", "id"),
				),
			},
			// Second step: same config, verifies idempotency (no changes on re-plan)
			{
				Config:   config,
				PlanOnly: true,
			},
		},
	})
}
