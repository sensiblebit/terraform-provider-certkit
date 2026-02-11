package provider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/sensiblebit/certkit"
)

var _ datasource.DataSource = &pkcs7DataSource{}

type pkcs7Model struct {
	// Input
	Content types.String `tfsdk:"content"`

	// Outputs
	Certificates types.List   `tfsdk:"certificates"`
	ID           types.String `tfsdk:"id"`
}

type pkcs7DataSource struct{}

func NewPKCS7DataSource() datasource.DataSource {
	return &pkcs7DataSource{}
}

func (d *pkcs7DataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pkcs7"
}

var pkcs7CertObjectType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"cert_pem":             types.StringType,
		"subject_common_name":  types.StringType,
		"sha256_fingerprint":   types.StringType,
	},
}

func (d *pkcs7DataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Decodes a PKCS#7/P7B bundle and exposes the certificates it contains.",
		Attributes: map[string]schema.Attribute{
			"content": schema.StringAttribute{
				Description: "Base64-encoded PKCS#7/P7B bundle to decode.",
				Required:    true,
			},
			"certificates": schema.ListNestedAttribute{
				Description: "Certificates extracted from the PKCS#7 bundle.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"cert_pem": schema.StringAttribute{
							Description: "PEM-encoded certificate.",
							Computed:    true,
						},
						"subject_common_name": schema.StringAttribute{
							Description: "Common Name (CN) from the certificate subject.",
							Computed:    true,
						},
						"sha256_fingerprint": schema.StringAttribute{
							Description: "SHA-256 fingerprint of the certificate.",
							Computed:    true,
						},
					},
				},
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

	// Base64-decode the PKCS#7 content
	derData, err := base64.StdEncoding.DecodeString(data.Content.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid Base64", fmt.Sprintf("Failed to decode base64 content: %s", err))
		return
	}

	// Decode PKCS#7
	certs, err := certkit.DecodePKCS7(derData)
	if err != nil {
		resp.Diagnostics.AddError("PKCS#7 Decoding Failed", err.Error())
		return
	}

	// Build certificate list
	certObjects := make([]types.Object, len(certs))
	for i, cert := range certs {
		certObjects[i], _ = types.ObjectValue(
			pkcs7CertObjectType.AttrTypes,
			map[string]attr.Value{
				"cert_pem":            types.StringValue(certkit.CertToPEM(cert)),
				"subject_common_name": types.StringValue(cert.Subject.CommonName),
				"sha256_fingerprint":  types.StringValue(certkit.CertFingerprint(cert)),
			},
		)
	}
	data.Certificates, _ = types.ListValue(pkcs7CertObjectType, certObjectsToValues(certObjects))

	// ID from hash of all cert DER bytes
	h := sha256.New()
	for _, cert := range certs {
		h.Write(cert.Raw)
	}
	data.ID = types.StringValue(fmt.Sprintf("%x", h.Sum(nil)[:8]))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func certObjectsToValues(objects []types.Object) []attr.Value {
	values := make([]attr.Value, len(objects))
	for i, o := range objects {
		values[i] = o
	}
	return values
}
