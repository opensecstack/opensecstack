package reporter

import (
	"fmt"

	"github.com/opensecstack/apiguard/internal/domain"
)

// Reporter generates a scan report in a specific format.
type Reporter interface {
	// Generate produces a serialised report from the given scan result.
	Generate(result *domain.ScanResult) ([]byte, error)
}

// New returns a Reporter for the requested format.
// Supported formats: "json", "sarif", "html", "pdf".
func New(format string) (Reporter, error) {
	switch format {
	case "json":
		return &JSONReporter{}, nil
	case "sarif":
		return &SARIFReporter{}, nil
	case "html":
		return &HTMLReporter{}, nil
	case "pdf":
		return &PDFReporter{}, nil
	default:
		return nil, fmt.Errorf("unsupported report format: %q", format)
	}
}
