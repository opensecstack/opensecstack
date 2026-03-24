package domain

// OWASPModule describes an OWASP API Security Top 10 check module.
type OWASPModule struct {
	ID          string // e.g. a1_bola
	OWASPId     string // e.g. API1:2023
	Name        string // e.g. Broken Object Level Authorization
	Description string
	Enabled     bool
	Default     bool
}

// DefaultModules lists the OWASP API Security Top 10 (2023) modules
// with their default enablement state.
var DefaultModules = []OWASPModule{
	{ID: "a1_bola", OWASPId: "API1:2023", Name: "Broken Object Level Authorization", Enabled: true, Default: true},
	{ID: "a2_auth", OWASPId: "API2:2023", Name: "Broken Authentication", Enabled: true, Default: true},
	{ID: "a3_mass_assignment", OWASPId: "API3:2023", Name: "Broken Object Property Level Authorization", Enabled: true, Default: true},
	{ID: "a4_rate_limiting", OWASPId: "API4:2023", Name: "Unrestricted Resource Consumption", Enabled: true, Default: true},
	{ID: "a5_function_auth", OWASPId: "API5:2023", Name: "Broken Function Level Authorization", Enabled: true, Default: true},
	{ID: "a6_business_flow", OWASPId: "API6:2023", Name: "Unrestricted Access to Sensitive Business Flows", Enabled: false, Default: false},
	{ID: "a7_ssrf", OWASPId: "API7:2023", Name: "Server Side Request Forgery", Enabled: true, Default: true},
	{ID: "a8_misconfig", OWASPId: "API8:2023", Name: "Security Misconfiguration", Enabled: true, Default: true},
	{ID: "a9_inventory", OWASPId: "API9:2023", Name: "Improper Inventory Management", Enabled: true, Default: true},
	{ID: "a10_unsafe_consumption", OWASPId: "API10:2023", Name: "Unsafe Consumption of APIs", Enabled: false, Default: false},
}
