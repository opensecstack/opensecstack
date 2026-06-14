package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// HTMLRenderer delegates HTML generation to a Python/Jinja2 subprocess.
// The Report is marshalled to JSON and piped to the subprocess via stdin;
// rendered HTML is read from stdout.
type HTMLRenderer struct {
	PythonBin    string // default "python3"
	ReporterPath string // default "python/reporter/main.py"
}

func (h *HTMLRenderer) Render(ctx context.Context, w io.Writer, r Report) error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("reporter: marshal: %w", err)
	}

	bin := h.PythonBin
	if bin == "" {
		bin = "python3"
	}
	path := h.ReporterPath
	if path == "" {
		path = "python/reporter/main.py"
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, path)
	cmd.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("reporter: python render: %w: %s", err, stderr.String())
	}
	_, err = w.Write(out)
	return err
}
