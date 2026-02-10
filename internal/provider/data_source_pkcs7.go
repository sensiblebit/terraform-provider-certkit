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

var _ datasource.DataSource = &pkcs7DataSource{}

type pkcs7Model struct {
	// Inputs
	CertPEM    types.String `tfsdk:"cert_pem"`
	CACertsPEM types.List   `tfsdk:"ca_certs_pem"`

	// Outputs
	Content types.String `tfsdk:"content"`
	ID      types.String `tfsdk:"id"`
}

type pkcs7DataSource struct{}

func NewPKCS7DataSource() datasource.DataSource {
	return &pkcs7DataSource{}
}

func (d *pkcs7DataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pkcs7"
}

func (d *pkcs7DataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Encodes certificates into a PKCS#7/P7B bundle (certs only, no private key).",
		Attributes: map[string]schema.Attribute{
			"cert_pem": schema.StringAttribute{
				Description: "PEM-encoded primary certificate to include.",
				Optional:    true,
			},
			"ca_certs_pem": schema.ListAttribute{
				Description: "PEM-encoded CA certificates to include in the bundle.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"content": schema.StringAttribute{
				Description: "Base64-encoded PKCS#7/P7B bundle.",
				Computed:    true,
			},
			"id": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func (d *pkcs7DataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data pkcs7Model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var allCerts []*x509.Certificate

	// Parse primary cert
	if !data.CertPEM.IsNull() && data.CertPEM.ValueString() != "" {
		cert, err := ParsePEMCertificate([]byte(data.CertPEM.ValueString()))
		if err != nil {
			resp.Diagnostics.AddError("Invalid Certificate", err.Error())
			return
		}
		allCerts = append(allCerts, cert)
	}

	// Parse CA certs
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
			allCerts = append(allCerts, certs...)
		}
	}

	// Validate at least one cert
	if len(allCerts) == 0 {
		resp.Diagnostics.AddError(
			"Invalid Configuration",
			"At least one of cert_pem or ca_certs_pem must be set.",
		)
		return
	}

	// Encode PKCS#7
	p7bData, err := EncodePKCS7(allCerts)
	if err != nil {
		resp.Diagnostics.AddError("PKCS#7 Encoding Failed", err.Error())
		return
	}

	data.Content = types.StringValue(base64.StdEncoding.EncodeToString(p7bData))

	// ID from hash of all cert DER bytes
	h := sha256.New()
	for _, cert := range allCerts {
		h.Write(cert.Raw)
	}
	data.ID = types.StringValue(fmt.Sprintf("%x", h.Sum(nil)[:8]))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
