package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

	required := []string{"cert_pem"}
	optionalComputed := []string{"private_key_pem"}
	computed := []string{"cert_request_pem", "key_algorithm", "id"}
	for _, attr := range slices.Concat(required, optionalComputed, computed) {
		if _, ok := schemaResp.Schema.Attributes[attr]; !ok {
			t.Errorf("missing attribute %q", attr)
		}
	}
}

// TestAccCertRequestDataSource_withKey tests CSR generation with a provided private key.
func TestAccCertRequestDataSource_withKey(t *testing.T) {
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

data "certkit_cert_request" "test" {
  cert_pem        = data.certkit_certificate.test.cert_pem
  private_key_pem = <<-EOT
%sEOT
}
`, leafPEM, intermediatePEM, caPEM, leafKeyPEM)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.certkit_cert_request.test", "cert_request_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_cert_request.test", "private_key_pem"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.test", "key_algorithm", "ECDSA"),
			),
		}},
	})
}

// TestAccCertRequestDataSource_autoGen tests CSR generation with auto-generated key.
func TestAccCertRequestDataSource_autoGen(t *testing.T) {
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

data "certkit_cert_request" "test" {
  cert_pem = data.certkit_certificate.test.cert_pem
}
`, leafPEM, intermediatePEM, caPEM)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.certkit_cert_request.test", "cert_request_pem"),
				resource.TestCheckResourceAttrSet("data.certkit_cert_request.test", "private_key_pem"),
				resource.TestCheckResourceAttr("data.certkit_cert_request.test", "key_algorithm", "ECDSA"),
			),
		}},
	})
}

func TestKeyAlgorithmName(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name     string
		key      interface{}
		expected string
	}{
		{"ECDSA", ecKey, "ECDSA"},
		{"RSA", rsaKey, "RSA"},
		{"Ed25519", edKey, "Ed25519"},
		{"nil", nil, "unknown"},
		{"unsupported", struct{}{}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := keyAlgorithmName(tt.key)
			if got != tt.expected {
				t.Errorf("keyAlgorithmName(%T) = %q, want %q", tt.key, got, tt.expected)
			}
		})
	}
}
