package provider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &certRequestDataSource{}

type certRequestModel struct {
	// Inputs
	CertPEM       types.String `tfsdk:"cert_pem"`
	PrivateKeyPEM types.String `tfsdk:"private_key_pem"`

	// Outputs
	CertRequestPEM types.String `tfsdk:"cert_request_pem"`
	KeyAlgorithm   types.String `tfsdk:"key_algorithm"`
	ID             types.String `tfsdk:"id"`
}

type certRequestDataSource struct{}

func NewCertRequestDataSource() datasource.DataSource {
	return &certRequestDataSource{}
}

func (d *certRequestDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cert_request"
}

func (d *certRequestDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Generates a Certificate Signing Request (CSR) by copying Subject and SANs from an existing certificate.",
		Attributes: map[string]schema.Attribute{
			"cert_pem": schema.StringAttribute{
				Description: "PEM-encoded certificate to copy Subject and SANs from.",
				Required:    true,
			},
			"private_key_pem": schema.StringAttribute{
				Description: "PEM-encoded private key for signing the CSR. If omitted, an EC P-256 key is auto-generated (changes every apply).",
				Optional:    true,
				Computed:    true,
				Sensitive:   true,
			},
			"cert_request_pem": schema.StringAttribute{
				Description: "PEM-encoded Certificate Signing Request.",
				Computed:    true,
			},
			"key_algorithm": schema.StringAttribute{
				Description: "Algorithm of the private key used: ECDSA, RSA, or Ed25519.",
				Computed:    true,
			},
			"id": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func (d *certRequestDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data certRequestModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Parse leaf certificate
	leaf, err := ParsePEMCertificate([]byte(data.CertPEM.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Invalid Certificate", err.Error())
		return
	}

	// Parse or auto-generate private key
	var parsedKey crypto.PrivateKey
	if !data.PrivateKeyPEM.IsNull() && data.PrivateKeyPEM.ValueString() != "" {
		var err error
		parsedKey, err = ParsePEMPrivateKey([]byte(data.PrivateKeyPEM.ValueString()))
		if err != nil {
			resp.Diagnostics.AddError("Invalid Private Key", err.Error())
			return
		}
	}

	// Generate CSR (nil key => auto-generate EC P-256)
	csrPEM, keyPEM, err := GenerateCSR(leaf, parsedKey)
	if err != nil {
		resp.Diagnostics.AddError("CSR Generation Failed", err.Error())
		return
	}

	data.CertRequestPEM = types.StringValue(csrPEM)

	// Set private_key_pem: passthrough if provided, auto-generated if not
	if keyPEM != "" {
		// Auto-generated
		data.PrivateKeyPEM = types.StringValue(keyPEM)
	}
	// If user provided the key, it stays as-is from config

	// Determine key algorithm
	var signerKey crypto.PrivateKey
	if parsedKey != nil {
		signerKey = parsedKey
	} else {
		// Parse the auto-generated key to determine type
		signerKey, _ = ParsePEMPrivateKey([]byte(data.PrivateKeyPEM.ValueString()))
	}
	data.KeyAlgorithm = types.StringValue(keyAlgorithmName(signerKey))

	// ID from leaf cert hash
	idHash := sha256.Sum256(leaf.Raw)
	data.ID = types.StringValue(fmt.Sprintf("%x", idHash[:8]))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func keyAlgorithmName(key crypto.PrivateKey) string {
	switch key.(type) {
	case *ecdsa.PrivateKey:
		return "ECDSA"
	case *rsa.PrivateKey:
		return "RSA"
	case ed25519.PrivateKey:
		return "Ed25519"
	default:
		return "unknown"
	}
}
