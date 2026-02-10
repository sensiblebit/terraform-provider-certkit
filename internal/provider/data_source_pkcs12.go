package provider

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &pkcs12DataSource{}

type pkcs12Model struct {
	// Inputs
	CertPEM       types.String `tfsdk:"cert_pem"`
	CACertsPEM    types.List   `tfsdk:"ca_certs_pem"`
	PrivateKeyPEM types.String `tfsdk:"private_key_pem"`
	Password      types.String `tfsdk:"password"`

	// Outputs
	Content types.String `tfsdk:"content"`
	ID      types.String `tfsdk:"id"`
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
		Description: "Encodes a certificate, CA chain, and private key into a PKCS#12/PFX bundle.",
		Attributes: map[string]schema.Attribute{
			"cert_pem": schema.StringAttribute{
				Description: "PEM-encoded leaf certificate.",
				Required:    true,
			},
			"ca_certs_pem": schema.ListAttribute{
				Description: "PEM-encoded CA certificates to include in the bundle.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"private_key_pem": schema.StringAttribute{
				Description: "PEM-encoded private key for the leaf certificate.",
				Required:    true,
				Sensitive:   true,
			},
			"password": schema.StringAttribute{
				Description: "Password for PKCS#12 encryption. Default: empty string.",
				Optional:    true,
				Sensitive:   true,
			},
			"content": schema.StringAttribute{
				Description: "Base64-encoded PKCS#12/PFX bundle.",
				Computed:    true,
				Sensitive:   true,
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

	// Parse leaf certificate
	leaf, err := ParsePEMCertificate([]byte(data.CertPEM.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Invalid Certificate", err.Error())
		return
	}

	// Parse private key
	parsedKey, err := ParsePEMPrivateKey([]byte(data.PrivateKeyPEM.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Invalid Private Key", err.Error())
		return
	}

	// Parse CA certs
	var caCerts []*x509.Certificate
	if !data.CACertsPEM.IsNull() {
		var caPEMs []string
		resp.Diagnostics.Append(data.CACertsPEM.ElementsAs(ctx, &caPEMs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, p := range caPEMs {
			certs, err := ParsePEMCertificates([]byte(p))
			if err != nil {
				resp.Diagnostics.AddError("Invalid CA Certificate", err.Error())
				return
			}
			caCerts = append(caCerts, certs...)
		}
	}

	// Password
	password := ""
	if !data.Password.IsNull() {
		password = data.Password.ValueString()
	}

	// Encode PKCS#12
	pfxData, err := EncodePKCS12(parsedKey, leaf, caCerts, password)
	if err != nil {
		resp.Diagnostics.AddError("PKCS#12 Encoding Failed", err.Error())
		return
	}

	data.Content = types.StringValue(base64.StdEncoding.EncodeToString(pfxData))

	// ID from leaf cert hash
	idHash := sha256.Sum256(leaf.Raw)
	data.ID = types.StringValue(fmt.Sprintf("%x", idHash[:8]))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
