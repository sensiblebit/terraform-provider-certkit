package provider

import (
	"context"
	"crypto"
	"crypto/sha256"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &certRequestResource{}

type certRequestResourceModel struct {
	CertPEM        types.String `tfsdk:"cert_pem"`
	PrivateKeyPEM  types.String `tfsdk:"private_key_pem"`
	CertRequestPEM types.String `tfsdk:"cert_request_pem"`
	KeyAlgorithm   types.String `tfsdk:"key_algorithm"`
	ID             types.String `tfsdk:"id"`
}

type certRequestResource struct{}

func NewCertRequestResource() resource.Resource {
	return &certRequestResource{}
}

func (r *certRequestResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cert_request"
}

func (r *certRequestResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Generates a Certificate Signing Request (CSR) by copying Subject and SANs from an existing certificate. The private key is stored in state.",
		Attributes: map[string]schema.Attribute{
			"cert_pem": schema.StringAttribute{
				Description: "PEM-encoded certificate to copy Subject and SANs from.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"private_key_pem": schema.StringAttribute{
				Description: "PEM-encoded private key for signing the CSR. If omitted, an EC P-256 key is auto-generated.",
				Optional:    true,
				Computed:    true,
				Sensitive:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
					stringplanmodifier.UseStateForUnknown(),
				},
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
				Description: "Computed identifier derived from the certificate.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *certRequestResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data certRequestResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
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
	if !data.PrivateKeyPEM.IsNull() && !data.PrivateKeyPEM.IsUnknown() && data.PrivateKeyPEM.ValueString() != "" {
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
		data.PrivateKeyPEM = types.StringValue(keyPEM)
	}

	// Determine key algorithm
	var signerKey crypto.PrivateKey
	if parsedKey != nil {
		signerKey = parsedKey
	} else {
		signerKey, _ = ParsePEMPrivateKey([]byte(data.PrivateKeyPEM.ValueString()))
	}
	data.KeyAlgorithm = types.StringValue(KeyAlgorithmName(signerKey))

	// ID from leaf cert hash
	idHash := sha256.Sum256(leaf.Raw)
	data.ID = types.StringValue(fmt.Sprintf("%x", idHash[:8]))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *certRequestResource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
	// No-op: state is self-contained. CSR was computed in Create, and ECDSA
	// signatures are non-deterministic so we cannot recompute.
}

func (r *certRequestResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
	// Never called: all inputs use RequiresReplace.
}

func (r *certRequestResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No-op: nothing external to clean up.
}
