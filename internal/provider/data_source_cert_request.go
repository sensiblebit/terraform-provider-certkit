package provider

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &certRequestDataSource{}

type certRequestModel struct {
	// Input
	CertRequestPEM types.String `tfsdk:"cert_request_pem"`

	// Outputs
	SubjectCommonName  types.String `tfsdk:"subject_common_name"`
	SubjectOrganization types.List   `tfsdk:"subject_organization"`
	SubjectCountry     types.List   `tfsdk:"subject_country"`
	DNSNames           types.List   `tfsdk:"dns_names"`
	IPAddresses        types.List   `tfsdk:"ip_addresses"`
	URIs               types.List   `tfsdk:"uris"`
	KeyAlgorithm       types.String `tfsdk:"key_algorithm"`
	SignatureAlgorithm types.String `tfsdk:"signature_algorithm"`
	ID                 types.String `tfsdk:"id"`
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
		Description: "Parses a PEM-encoded Certificate Signing Request (CSR) and exposes its subject, SANs, and key details.",
		Attributes: map[string]schema.Attribute{
			"cert_request_pem": schema.StringAttribute{
				Description: "PEM-encoded Certificate Signing Request to inspect.",
				Required:    true,
			},
			"subject_common_name": schema.StringAttribute{
				Description: "Common Name (CN) from the CSR subject.",
				Computed:    true,
			},
			"subject_organization": schema.ListAttribute{
				Description: "Organization (O) values from the CSR subject.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"subject_country": schema.ListAttribute{
				Description: "Country (C) values from the CSR subject.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"dns_names": schema.ListAttribute{
				Description: "DNS Subject Alternative Names from the CSR.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"ip_addresses": schema.ListAttribute{
				Description: "IP address Subject Alternative Names from the CSR.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"uris": schema.ListAttribute{
				Description: "URI Subject Alternative Names from the CSR.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"key_algorithm": schema.StringAttribute{
				Description: "Algorithm of the public key: ECDSA, RSA, or Ed25519.",
				Computed:    true,
			},
			"signature_algorithm": schema.StringAttribute{
				Description: "Signature algorithm used to sign the CSR.",
				Computed:    true,
			},
			"id": schema.StringAttribute{
				Description: "Computed identifier derived from the CSR.",
				Computed:    true,
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

	// Parse CSR
	csr, err := ParsePEMCertificateRequest([]byte(data.CertRequestPEM.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Invalid Certificate Request", err.Error())
		return
	}

	// Verify signature
	if err := csr.CheckSignature(); err != nil {
		resp.Diagnostics.AddError("CSR Signature Verification Failed", err.Error())
		return
	}

	// Subject fields
	data.SubjectCommonName = types.StringValue(csr.Subject.CommonName)

	orgValues := make([]types.String, len(csr.Subject.Organization))
	for i, o := range csr.Subject.Organization {
		orgValues[i] = types.StringValue(o)
	}
	data.SubjectOrganization, _ = types.ListValueFrom(ctx, types.StringType, orgValues)

	countryValues := make([]types.String, len(csr.Subject.Country))
	for i, c := range csr.Subject.Country {
		countryValues[i] = types.StringValue(c)
	}
	data.SubjectCountry, _ = types.ListValueFrom(ctx, types.StringType, countryValues)

	// SAN fields
	dnsValues := make([]types.String, len(csr.DNSNames))
	for i, d := range csr.DNSNames {
		dnsValues[i] = types.StringValue(d)
	}
	data.DNSNames, _ = types.ListValueFrom(ctx, types.StringType, dnsValues)

	ipValues := make([]types.String, len(csr.IPAddresses))
	for i, ip := range csr.IPAddresses {
		ipValues[i] = types.StringValue(ip.String())
	}
	data.IPAddresses, _ = types.ListValueFrom(ctx, types.StringType, ipValues)

	uriValues := make([]types.String, len(csr.URIs))
	for i, u := range csr.URIs {
		uriValues[i] = types.StringValue(u.String())
	}
	data.URIs, _ = types.ListValueFrom(ctx, types.StringType, uriValues)

	// Key and signature info
	data.KeyAlgorithm = types.StringValue(PublicKeyAlgorithmName(csr.PublicKey))
	data.SignatureAlgorithm = types.StringValue(csr.SignatureAlgorithm.String())

	// ID from CSR raw bytes hash
	idHash := sha256.Sum256(csr.Raw)
	data.ID = types.StringValue(fmt.Sprintf("%x", idHash[:8]))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
