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

var _ resource.Resource = &pkcs12Resource{}

type pkcs12ResourceModel struct {
	// Inputs
	CertPEM       types.String `tfsdk:"cert_pem"`
	CACertsPEM    types.List   `tfsdk:"ca_certs_pem"`
	PrivateKeyPEM types.String `tfsdk:"private_key_pem"`
	Password      types.String `tfsdk:"password"`

	// Outputs
	Content types.String `tfsdk:"content"`
	ID      types.String `tfsdk:"id"`
}

type pkcs12Resource struct{}

func NewPKCS12Resource() resource.Resource {
	return &pkcs12Resource{}
}

func (r *pkcs12Resource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pkcs12"
}

func (r *pkcs12Resource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Encodes a certificate, CA chain, and private key into a PKCS#12/PFX bundle. The bundle is stored in state.",
		Attributes: map[string]schema.Attribute{
			"cert_pem": schema.StringAttribute{
				Description: "PEM-encoded leaf certificate.",
				Required:    true,
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
			"private_key_pem": schema.StringAttribute{
				Description: "PEM-encoded private key for the leaf certificate.",
				Required:    true,
				Sensitive:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"password": schema.StringAttribute{
				Description: "Password for PKCS#12 encryption. Default: empty string.",
				Optional:    true,
				Sensitive:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"content": schema.StringAttribute{
				Description: "Base64-encoded PKCS#12/PFX bundle.",
				Computed:    true,
				Sensitive:   true,
			},
			"id": schema.StringAttribute{
				Description: "Computed identifier derived from the leaf certificate.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *pkcs12Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data pkcs12ResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Parse leaf certificate
	leaf, err := certkit.ParsePEMCertificate([]byte(data.CertPEM.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Invalid Certificate", err.Error())
		return
	}

	// Parse private key
	parsedKey, err := certkit.ParsePEMPrivateKey([]byte(data.PrivateKeyPEM.ValueString()))
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
			certs, err := certkit.ParsePEMCertificates([]byte(p))
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
	pfxData, err := certkit.EncodePKCS12(parsedKey, leaf, caCerts, password)
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

func (r *pkcs12Resource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
	// No-op: state is self-contained. PKCS#12 encoding is non-deterministic
	// so we cannot recompute.
}

func (r *pkcs12Resource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
	// Never called: all inputs use RequiresReplace.
}

func (r *pkcs12Resource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No-op: nothing external to clean up.
}
