package provider

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/sensiblebit/certkit"
)

var _ resource.Resource = &pkcs7Resource{}

type pkcs7ResourceModel struct {
	// Inputs
	CertPEM    types.String `tfsdk:"cert_pem"`
	CACertsPEM types.List   `tfsdk:"ca_certs_pem"`

	// Outputs
	Content types.String `tfsdk:"content"`
	ID      types.String `tfsdk:"id"`
}

type pkcs7Resource struct{}

func NewPKCS7Resource() resource.Resource {
	return &pkcs7Resource{}
}

func (r *pkcs7Resource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pkcs7"
}

func (r *pkcs7Resource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Encodes certificates into a PKCS#7/P7B bundle (certs only, no private key). The bundle is stored in state.",
		Attributes: map[string]schema.Attribute{
			"cert_pem": schema.StringAttribute{
				Description: "PEM-encoded primary certificate to include.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ca_certs_pem": schema.ListAttribute{
				Description: "PEM-encoded CA certificates to include in the bundle.",
				Optional:    true,
				ElementType: types.StringType,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
			},
			"content": schema.StringAttribute{
				Description: "Base64-encoded PKCS#7/P7B bundle.",
				Computed:    true,
			},
			"id": schema.StringAttribute{
				Description: "Computed identifier derived from the certificates.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *pkcs7Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data pkcs7ResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var allCerts []*x509.Certificate

	// Parse primary cert
	if !data.CertPEM.IsNull() && data.CertPEM.ValueString() != "" {
		cert, err := certkit.ParsePEMCertificate([]byte(data.CertPEM.ValueString()))
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
			certs, err := certkit.ParsePEMCertificates([]byte(p))
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
	p7bData, err := certkit.EncodePKCS7(allCerts)
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

func (r *pkcs7Resource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
	// No-op: state is self-contained.
}

func (r *pkcs7Resource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
	// Never called: all inputs use RequiresReplace.
}

func (r *pkcs7Resource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No-op: nothing external to clean up.
}
