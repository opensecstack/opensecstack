package reporter

import (
	"encoding/json"
	"fmt"
	"io"
)

func generateJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("reporter: json encode: %w", err)
	}
	return nil
}
