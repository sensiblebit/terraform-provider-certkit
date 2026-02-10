package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ provider.Provider = &certkitProvider{}

type certkitProvider struct {
	version string
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &certkitProvider{version: version}
	}
}

func (p *certkitProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "certkit"
	resp.Version = p.version
}

func (p *certkitProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Certificate toolkit: resolves chains, exports PEM/PKCS#12/PKCS#7, generates CSRs.",
	}
}

func (p *certkitProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
	// No provider-level configuration needed.
}

func (p *certkitProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewCertificateDataSource,
		NewPKCS12DataSource,
		NewPKCS7DataSource,
		NewCertRequestDataSource,
	}
}

func (p *certkitProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewCertRequestResource,
		NewPKCS12Resource,
		NewPKCS7Resource,
	}
}
