package reporter

import (
	"context"
	"fmt"
	"io"
)

type Format string

const (
	FormatJSON  Format = "json"
	FormatHTML  Format = "html"
	FormatSARIF Format = "sarif"
)

// Report is the input to the generator. Result holds the raw scan
// outcome from any of the scanner modules (prompt, phishing, media,
// identity).
type Report struct {
	ScanID      string `json:"scan_id"`
	ScanType    string `json:"scan_type"`    // "prompt" | "media" | "phishing" | "identity"
	Result      any    `json:"result"`       // raw scan result from the relevant module
	GeneratedAt string `json:"generated_at"` // RFC3339
}

// Generator dispatches a Report to the correct formatter.
type Generator struct {
	htmlRenderer *HTMLRenderer
}

func NewGenerator() *Generator {
	return &Generator{htmlRenderer: &HTMLRenderer{}}
}

func (g *Generator) Generate(ctx context.Context, w io.Writer, r Report, format Format) error {
	switch format {
	case FormatJSON:
		return generateJSON(w, r)
	case FormatHTML:
		return g.htmlRenderer.Render(ctx, w, r)
	case FormatSARIF:
		return generateSARIF(w, r)
	default:
		return fmt.Errorf("reporter: unsupported format %q", format)
	}
}
