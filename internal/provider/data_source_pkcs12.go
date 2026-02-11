package provider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/sensiblebit/certkit"
)

var _ datasource.DataSource = &pkcs12DataSource{}

type pkcs12Model struct {
	// Input
	Content  types.String `tfsdk:"content"`
	Password types.String `tfsdk:"password"`

	// Outputs
	CertPEM       types.String `tfsdk:"cert_pem"`
	PrivateKeyPEM types.String `tfsdk:"private_key_pem"`
	CACertsPEM    types.List   `tfsdk:"ca_certs_pem"`
	KeyAlgorithm  types.String `tfsdk:"key_algorithm"`
	ID            types.String `tfsdk:"id"`
}

type pkcs12DataSource struct{}

func NewPKCS12DataSource() datasource.DataSource {
	return &pkcs12DataSource{}
}

func (d *pkcs12DataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pkcs12"
}

func (d *pkcs12DataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Decodes a PKCS#12/PFX bundle and exposes its certificate, private key, and CA chain.",
		Attributes: map[string]schema.Attribute{
			"content": schema.StringAttribute{
				Description: "Base64-encoded PKCS#12/PFX bundle to decode.",
				Required:    true,
				Sensitive:   true,
			},
			"password": schema.StringAttribute{
				Description: "Password for PKCS#12 decryption. Default: empty string.",
				Optional:    true,
				Sensitive:   true,
			},
			"cert_pem": schema.StringAttribute{
				Description: "PEM-encoded leaf certificate extracted from the bundle.",
				Computed:    true,
			},
			"private_key_pem": schema.StringAttribute{
				Description: "PEM-encoded private key extracted from the bundle (PKCS#8 format).",
				Computed:    true,
				Sensitive:   true,
			},
			"ca_certs_pem": schema.ListAttribute{
				Description: "PEM-encoded CA certificates extracted from the bundle.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"key_algorithm": schema.StringAttribute{
				Description: "Algorithm of the private key: ECDSA, RSA, or Ed25519.",
				Computed:    true,
			},
			"id": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func (d *pkcs12DataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data pkcs12Model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Base64-decode the PKCS#12 content
	pfxData, err := base64.StdEncoding.DecodeString(data.Content.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid Base64", fmt.Sprintf("Failed to decode base64 content: %s", err))
		return
	}

	// Password
	password := ""
	if !data.Password.IsNull() {
		password = data.Password.ValueString()
	}

	// Decode PKCS#12
	privateKey, leaf, caCerts, err := certkit.DecodePKCS12(pfxData, password)
	if err != nil {
		resp.Diagnostics.AddError("PKCS#12 Decoding Failed", err.Error())
		return
	}

	// Leaf cert PEM
	data.CertPEM = types.StringValue(certkit.CertToPEM(leaf))

	// Private key PEM (PKCS#8)
	keyPEM, err := certkit.MarshalPrivateKeyToPEM(privateKey)
	if err != nil {
		resp.Diagnostics.AddError("Private Key Marshal Failed", err.Error())
		return
	}
	data.PrivateKeyPEM = types.StringValue(keyPEM)

	// CA certs PEM list
	caPEMValues := make([]types.String, len(caCerts))
	for i, ca := range caCerts {
		caPEMValues[i] = types.StringValue(certkit.CertToPEM(ca))
	}
	data.CACertsPEM, _ = types.ListValueFrom(ctx, types.StringType, caPEMValues)

	// Key algorithm
	data.KeyAlgorithm = types.StringValue(certkit.KeyAlgorithmName(privateKey))

	// ID from leaf cert hash
	idHash := sha256.Sum256(leaf.Raw)
	data.ID = types.StringValue(fmt.Sprintf("%x", idHash[:8]))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
