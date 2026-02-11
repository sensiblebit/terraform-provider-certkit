package provider

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/sensiblebit/certkit"
)

var _ datasource.DataSource = &certificateDataSource{}

// certInfoAttrTypesNew defines the object schema for per-cert metadata (new naming).
var certInfoAttrTypesNew = map[string]attr.Type{
	"cert_pem":            types.StringType,
	"sha256_fingerprint":  types.StringType,
	"ski":                types.StringType,
	"ski_embedded":       types.StringType,
	"aki":                types.StringType,
	"aki_embedded":       types.StringType,
}

type certificateModel struct {
	// Inputs
	URL                   types.String `tfsdk:"url"`
	LeafPEM               types.String `tfsdk:"leaf_pem"`
	ExtraIntermediatesPEM types.List   `tfsdk:"extra_intermediates_pem"`
	FetchAIA              types.Bool   `tfsdk:"fetch_aia"`
	AIATimeoutMs          types.Int64  `tfsdk:"aia_timeout_ms"`
	AIAMaxDepth           types.Int64  `tfsdk:"aia_max_depth"`
	TrustStore            types.String `tfsdk:"trust_store"`
	CustomRootsPEM        types.List   `tfsdk:"custom_roots_pem"`
	Verify                types.Bool   `tfsdk:"verify"`
	IncludeRoot           types.Bool   `tfsdk:"include_root"`
	ColonSeparated        types.Bool   `tfsdk:"colon_separated"`

	// Outputs - PEM
	CertPEM      types.String `tfsdk:"cert_pem"`
	ChainPEM     types.String `tfsdk:"chain_pem"`
	FullchainPEM types.String `tfsdk:"fullchain_pem"`

	// Outputs - Leaf fingerprints (flat)
	SHA256Fingerprint types.String `tfsdk:"sha256_fingerprint"`
	SKI              types.String `tfsdk:"ski"`
	SKIEmbedded      types.String `tfsdk:"ski_embedded"`
	AKI              types.String `tfsdk:"aki"`
	AKIEmbedded      types.String `tfsdk:"aki_embedded"`

	// Outputs - Structured cert lists
	Intermediates types.List `tfsdk:"intermediates"`
	Roots         types.List `tfsdk:"roots"`

	// Outputs - Debug
	Warnings types.List `tfsdk:"warnings"`

	// Computed
	ID types.String `tfsdk:"id"`
}

type certificateDataSource struct{}

func NewCertificateDataSource() datasource.DataSource {
	return &certificateDataSource{}
}

func (d *certificateDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

var certInfoNestedObjectNew = schema.NestedAttributeObject{
	Attributes: map[string]schema.Attribute{
		"cert_pem": schema.StringAttribute{
			Description: "Certificate in PEM format.",
			Computed:    true,
		},
		"sha256_fingerprint": schema.StringAttribute{
			Description: "SHA-256 fingerprint of the certificate DER encoding.",
			Computed:    true,
		},
		"ski": schema.StringAttribute{
			Description: "Subject Key Identifier (RFC 7093 Method 1: truncated SHA-256 of public key).",
			Computed:    true,
		},
		"ski_embedded": schema.StringAttribute{
			Description: "Subject Key Identifier as embedded in the certificate extension (may be SHA-1 or SHA-256).",
			Computed:    true,
		},
		"aki": schema.StringAttribute{
			Description: "Authority Key Identifier (RFC 7093 SKI of the issuer, matches issuer's ski).",
			Computed:    true,
		},
		"aki_embedded": schema.StringAttribute{
			Description: "Authority Key Identifier as embedded in the certificate extension (matches issuer's ski_embedded).",
			Computed:    true,
		},
	},
}

func (d *certificateDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Resolves a certificate chain from a leaf certificate and verifies it against a trust store.",
		Attributes: map[string]schema.Attribute{
			// --- Inputs ---
			"url": schema.StringAttribute{
				Description: "HTTPS URL to fetch the leaf certificate from via TLS handshake (e.g. https://example.com). Mutually exclusive with leaf_pem.",
				Optional:    true,
			},
			"leaf_pem": schema.StringAttribute{
				Description: "PEM-encoded leaf certificate. Mutually exclusive with url.",
				Optional:    true,
			},
			"extra_intermediates_pem": schema.ListAttribute{
				Description: "Additional PEM-encoded intermediate certificates to aid chain building.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"fetch_aia": schema.BoolAttribute{
				Description: "Fetch intermediate certificates via AIA (Authority Information Access) URLs. Default: true.",
				Optional:    true,
			},
			"aia_timeout_ms": schema.Int64Attribute{
				Description: "Timeout in milliseconds for each AIA HTTP fetch. Default: 2000.",
				Optional:    true,
			},
			"aia_max_depth": schema.Int64Attribute{
				Description: "Maximum number of AIA fetches to follow. Default: 5.",
				Optional:    true,
			},
			"trust_store": schema.StringAttribute{
				Description: "Trust store to use for verification: system, mozilla, or custom. Default: system.",
				Optional:    true,
			},
			"custom_roots_pem": schema.ListAttribute{
				Description: "PEM-encoded root certificates when trust_store is set to custom.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"verify": schema.BoolAttribute{
				Description: "Verify the certificate chain against the trust store. Default: true.",
				Optional:    true,
			},
			"include_root": schema.BoolAttribute{
				Description: "Include the root certificate in fullchain output. Default: true.",
				Optional:    true,
			},
			"colon_separated": schema.BoolAttribute{
				Description: "Use colon-separated hex for fingerprints, SKIs, and AKIs (e.g. ab:cd:ef). When false, outputs plain hex (e.g. abcdef). Default: true.",
				Optional:    true,
			},

			// --- Outputs: PEM ---
			"cert_pem": schema.StringAttribute{
				Description: "The leaf certificate in PEM format (normalized).",
				Computed:    true,
			},
			"chain_pem": schema.StringAttribute{
				Description: "Concatenated PEM: leaf + intermediates.",
				Computed:    true,
			},
			"fullchain_pem": schema.StringAttribute{
				Description: "Concatenated PEM: leaf + intermediates + root (if include_root is true).",
				Computed:    true,
			},

			// --- Outputs: Leaf fingerprints (flat) ---
			"sha256_fingerprint": schema.StringAttribute{
				Description: "SHA-256 fingerprint of the leaf certificate DER encoding.",
				Computed:    true,
			},
			"ski": schema.StringAttribute{
				Description: "Leaf Subject Key Identifier (RFC 7093 Method 1: truncated SHA-256 of public key).",
				Computed:    true,
			},
			"ski_embedded": schema.StringAttribute{
				Description: "Leaf Subject Key Identifier as embedded in the certificate extension.",
				Computed:    true,
			},
			"aki": schema.StringAttribute{
				Description: "Leaf Authority Key Identifier (RFC 7093 SKI of the issuer).",
				Computed:    true,
			},
			"aki_embedded": schema.StringAttribute{
				Description: "Leaf Authority Key Identifier as embedded in the certificate extension.",
				Computed:    true,
			},

			// --- Outputs: Structured cert lists ---
			"intermediates": schema.ListNestedAttribute{
				Description: "Intermediate certificates with metadata, ordered from leaf-issuer to root-issuer.",
				Computed:    true,
				NestedObject: certInfoNestedObjectNew,
			},
			"roots": schema.ListNestedAttribute{
				Description: "Root certificates with metadata.",
				Computed:    true,
				NestedObject: certInfoNestedObjectNew,
			},

			// --- Outputs: Debug ---
			"warnings": schema.ListAttribute{
				Description: "Non-fatal warnings (e.g., AIA fetch failures).",
				Computed:    true,
				ElementType: types.StringType,
			},

			// --- Computed ---
			"id": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func (d *certificateDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data certificateModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate: exactly one of url or leaf_pem must be set
	hasURL := !data.URL.IsNull() && data.URL.ValueString() != ""
	hasLeafPEM := !data.LeafPEM.IsNull() && data.LeafPEM.ValueString() != ""
	if hasURL == hasLeafPEM {
		resp.Diagnostics.AddError(
			"Invalid Configuration",
			"Exactly one of url or leaf_pem must be set.",
		)
		return
	}

	// Build options from inputs
	opts := certkit.DefaultOptions()

	aiaTimeoutMs := 2000
	if !data.AIATimeoutMs.IsNull() {
		aiaTimeoutMs = int(data.AIATimeoutMs.ValueInt64())
	}
	opts.AIATimeout = time.Duration(aiaTimeoutMs) * time.Millisecond

	// Obtain leaf certificate
	var leaf *x509.Certificate
	if hasURL {
		var err error
		leaf, err = certkit.FetchLeafFromURL(ctx, data.URL.ValueString(), opts.AIATimeout)
		if err != nil {
			resp.Diagnostics.AddError("Failed to Fetch Certificate", err.Error())
			return
		}
	} else {
		var err error
		leaf, err = certkit.ParsePEMCertificate([]byte(data.LeafPEM.ValueString()))
		if err != nil {
			resp.Diagnostics.AddError("Invalid Leaf Certificate", err.Error())
			return
		}
	}

	if !data.FetchAIA.IsNull() {
		opts.FetchAIA = data.FetchAIA.ValueBool()
	}
	if !data.AIAMaxDepth.IsNull() {
		opts.AIAMaxDepth = int(data.AIAMaxDepth.ValueInt64())
	}
	if !data.TrustStore.IsNull() {
		opts.TrustStore = data.TrustStore.ValueString()
	}
	if !data.Verify.IsNull() {
		opts.Verify = data.Verify.ValueBool()
	}
	if !data.IncludeRoot.IsNull() {
		opts.IncludeRoot = data.IncludeRoot.ValueBool()
	}

	// Validate: trust_store value
	switch opts.TrustStore {
	case "system", "mozilla", "custom":
		// valid
	default:
		resp.Diagnostics.AddError(
			"Invalid Configuration",
			fmt.Sprintf("trust_store must be \"system\", \"mozilla\", or \"custom\", got %q.", opts.TrustStore),
		)
		return
	}

	// Validate: custom trust_store requires custom_roots_pem
	if opts.TrustStore == "custom" && (data.CustomRootsPEM.IsNull() || len(data.CustomRootsPEM.Elements()) == 0) {
		resp.Diagnostics.AddError(
			"Invalid Configuration",
			"custom_roots_pem must be set when trust_store is \"custom\".",
		)
		return
	}

	// Parse extra intermediates
	if !data.ExtraIntermediatesPEM.IsNull() {
		var extraPEMs []string
		resp.Diagnostics.Append(data.ExtraIntermediatesPEM.ElementsAs(ctx, &extraPEMs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, p := range extraPEMs {
			certs, err := certkit.ParsePEMCertificates([]byte(p))
			if err != nil {
				resp.Diagnostics.AddError("Invalid Extra Intermediate", err.Error())
				return
			}
			opts.ExtraIntermediates = append(opts.ExtraIntermediates, certs...)
		}
	}

	// Parse custom roots
	if !data.CustomRootsPEM.IsNull() {
		var rootPEMs []string
		resp.Diagnostics.Append(data.CustomRootsPEM.ElementsAs(ctx, &rootPEMs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, p := range rootPEMs {
			certs, err := certkit.ParsePEMCertificates([]byte(p))
			if err != nil {
				resp.Diagnostics.AddError("Invalid Custom Root", err.Error())
				return
			}
			opts.CustomRoots = append(opts.CustomRoots, certs...)
		}
	}

	// Resolve chain
	result, err := certkit.Bundle(ctx, leaf, opts)
	if err != nil {
		resp.Diagnostics.AddError("Chain Resolution Failed", err.Error())
		return
	}

	// Colon separator preference
	colonSep := true
	if !data.ColonSeparated.IsNull() {
		colonSep = data.ColonSeparated.ValueBool()
	}
	formatHex := func(s string) string {
		if colonSep {
			return s
		}
		return strings.ReplaceAll(s, ":", "")
	}

	// Build PEM outputs
	leafPEM := certkit.CertToPEM(result.Leaf)
	data.CertPEM = types.StringValue(leafPEM)

	// Build ordered chain for AKI lookups: [leaf, int0, int1, ..., root]
	chain := make([]*x509.Certificate, 0, 1+len(result.Intermediates)+len(result.Roots))
	chain = append(chain, result.Leaf)
	chain = append(chain, result.Intermediates...)
	chain = append(chain, result.Roots...)

	akiForIndex := func(i int) string {
		if i+1 < len(chain) {
			return formatHex(certkit.CertSKID(chain[i+1]))
		}
		return formatHex(certkit.CertSKID(chain[i])) // self-signed root
	}

	// Leaf fingerprints (flat top-level attrs)
	data.SHA256Fingerprint = types.StringValue(certkit.CertFingerprint(result.Leaf))
	data.SKI = types.StringValue(formatHex(certkit.CertSKID(result.Leaf)))
	data.SKIEmbedded = types.StringValue(formatHex(certkit.CertSKIDEmbedded(result.Leaf)))
	data.AKI = types.StringValue(akiForIndex(0))
	data.AKIEmbedded = types.StringValue(formatHex(certkit.CertAKIDEmbedded(result.Leaf)))

	// Helper to build a cert info object
	buildCertInfo := func(cert *x509.Certificate, chainIdx int) (types.Object, error) {
		obj, diags := types.ObjectValue(certInfoAttrTypesNew, map[string]attr.Value{
			"cert_pem":            types.StringValue(certkit.CertToPEM(cert)),
			"sha256_fingerprint":  types.StringValue(certkit.CertFingerprint(cert)),
			"ski":                types.StringValue(formatHex(certkit.CertSKID(cert))),
			"ski_embedded":       types.StringValue(formatHex(certkit.CertSKIDEmbedded(cert))),
			"aki":                types.StringValue(akiForIndex(chainIdx)),
			"aki_embedded":       types.StringValue(formatHex(certkit.CertAKIDEmbedded(cert))),
		})
		if diags.HasError() {
			return types.ObjectNull(certInfoAttrTypesNew), fmt.Errorf("building cert info object: %s", diags.Errors())
		}
		return obj, nil
	}

	// Intermediates
	var chainParts []string
	chainParts = append(chainParts, leafPEM)

	var intermediateObjs []attr.Value
	for i, cert := range result.Intermediates {
		chainParts = append(chainParts, certkit.CertToPEM(cert))
		obj, err := buildCertInfo(cert, 1+i)
		if err != nil {
			resp.Diagnostics.AddError("Internal Error", err.Error())
			return
		}
		intermediateObjs = append(intermediateObjs, obj)
	}
	intermediatesList, diags := types.ListValue(types.ObjectType{AttrTypes: certInfoAttrTypesNew}, intermediateObjs)
	resp.Diagnostics.Append(diags...)
	data.Intermediates = intermediatesList

	// Roots
	var rootObjs []attr.Value
	for i, cert := range result.Roots {
		obj, err := buildCertInfo(cert, 1+len(result.Intermediates)+i)
		if err != nil {
			resp.Diagnostics.AddError("Internal Error", err.Error())
			return
		}
		rootObjs = append(rootObjs, obj)
	}
	rootsList, diags := types.ListValue(types.ObjectType{AttrTypes: certInfoAttrTypesNew}, rootObjs)
	resp.Diagnostics.Append(diags...)
	data.Roots = rootsList

	// Chain (leaf + intermediates)
	data.ChainPEM = types.StringValue(strings.Join(chainParts, ""))

	// Fullchain (leaf + intermediates + root)
	fullchainParts := make([]string, len(chainParts))
	copy(fullchainParts, chainParts)
	if opts.IncludeRoot {
		for _, cert := range result.Roots {
			fullchainParts = append(fullchainParts, certkit.CertToPEM(cert))
		}
	}
	data.FullchainPEM = types.StringValue(strings.Join(fullchainParts, ""))

	// Warnings
	var warnValues []attr.Value
	for _, w := range result.Warnings {
		warnValues = append(warnValues, types.StringValue(w))
	}
	warningsList, diags := types.ListValue(types.StringType, warnValues)
	resp.Diagnostics.Append(diags...)
	data.Warnings = warningsList

	// ID
	idHash := sha256.Sum256(result.Leaf.Raw)
	data.ID = types.StringValue(fmt.Sprintf("%x", idHash[:8]))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
