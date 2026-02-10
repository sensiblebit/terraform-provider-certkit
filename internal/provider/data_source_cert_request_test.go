package provider

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCertRequestDataSource(t *testing.T) {
	ctx := context.Background()
	ds := NewCertRequestDataSource()

	metaResp := &datasource.MetadataResponse{}
	ds.Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "certkit"}, metaResp)
	if metaResp.TypeName != "certkit_cert_request" {
		t.Errorf("got type=%q", metaResp.TypeName)
	}

	schemaResp := &datasource.SchemaResponse{}
	ds.Schema(ctx, datasource.SchemaRequest{}, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatal(schemaResp.Diagnostics)
	}

	required := []string{"cert_request_pem"}
	computed := []string{
		"subject_common_name", "subject_organization", "subject_country",
		"dns_names", "ip_addresses", "uris",
		"key_algorithm", "signature_algorithm", "id",
	}
	for _, attr := range slices.Concat(required, computed) {
		if _, ok := schemaResp.Schema.Attributes[attr]; !ok {
			t.Errorf("missing attribute %q", attr)
		}
	}
}

// TestAccCertRequestDataSource_roundTrip generates a CSR with the resource,
// then inspects it with the data source and verifies all parsed fields.
func TestAccCertRequestDataSource_roundTrip(t *testing.T) {
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

data "certkit_cert_request" "inspect" {
  cert_request_pem = certkit_cert_request.test.cert_request_pem
}
`, leafPEM, intermediatePEM, caPEM, leafKeyPEM)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "subject_common_name", "test.example.com"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "key_algorithm", "ECDSA"),
				resource.TestCheckResourceAttrSet("data.certkit_cert_request.inspect", "signature_algorithm"),
				resource.TestCheckResourceAttrSet("data.certkit_cert_request.inspect", "id"),
			),
		}},
	})
}

// TestAccCertRequestDataSource_withSANs generates a CSR from a cert with full SANs
// and verifies the data source parses all SAN types.
func TestAccCertRequestDataSource_withSANs(t *testing.T) {
	leaf, key := generateLeafWithSANs(t)

	csrPEM, _, err := GenerateCSR(leaf, key)
	if err != nil {
		t.Fatal(err)
	}

	config := fmt.Sprintf(`
provider "certkit" {}

data "certkit_cert_request" "inspect" {
  cert_request_pem = <<-EOT
%sEOT
}
`, csrPEM)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "subject_common_name", "test.example.com"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "subject_organization.#", "1"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "subject_organization.0", "Test Org"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "subject_country.#", "1"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "subject_country.0", "US"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "dns_names.#", "2"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "dns_names.0", "test.example.com"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "dns_names.1", "www.test.example.com"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "ip_addresses.#", "2"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "ip_addresses.0", "10.0.0.1"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "ip_addresses.1", "::1"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "uris.#", "1"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "uris.0", "spiffe://example.com/workload"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.inspect", "key_algorithm", "ECDSA"),
				resource.TestCheckResourceAttrSet("data.certkit_cert_request.inspect", "signature_algorithm"),
				resource.TestCheckResourceAttrSet("data.certkit_cert_request.inspect", "id"),
			),
		}},
	})
}
