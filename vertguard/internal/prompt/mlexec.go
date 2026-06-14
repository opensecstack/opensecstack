package prompt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// MLBackend is the v1.0 contract for an out-of-process ML detector.
// The Subprocess implementation pipes a single JSON request over stdin
// and reads a single JSON response from stdout. No streaming, no
// long-lived process — the goal is operator-friendly deployment, not
// minimum latency. The Rust optimisation in v1.1 will add a long-lived
// IPC backend behind the same interface.
//
// Implementations MUST be safe for concurrent use.
type MLBackend interface {
	Score(ctx context.Context, input, contextTag string) (*MLScore, error)
	AlwaysScore() bool
	Name() string
}

// MLExecConfig configures the subprocess backend.
type MLExecConfig struct {
	BinaryPath  string
	Timeout     time.Duration
	AlwaysScore bool
	// ExtraArgs is forwarded to the subprocess after BinaryPath. Useful
	// for passing model-version flags without rebuilding the binary.
	ExtraArgs []string
}

// mlExec implements MLBackend by exec()-ing a configured binary per
// scan. Empty BinaryPath disables the backend (Score is a no-op
// returning nil/nil so the scanner stays on regex+heuristics).
type mlExec struct {
	cfg MLExecConfig
}

// NewMLExec builds a subprocess MLBackend. A nil-but-typed return
// happens when BinaryPath is empty — callers should treat that as
// "ML disabled" and avoid wiring it to the scanner.
func NewMLExec(cfg MLExecConfig) MLBackend {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	return &mlExec{cfg: cfg}
}

func (m *mlExec) AlwaysScore() bool { return m.cfg.AlwaysScore }

func (m *mlExec) Name() string {
	if m.cfg.BinaryPath == "" {
		return "mlexec(disabled)"
	}
	return "mlexec(" + m.cfg.BinaryPath + ")"
}

// mlExecRequest is the wire schema sent on stdin. Keeping it tiny
// makes it easy for operators to script their own backend in any
// language.
type mlExecRequest struct {
	Input   string `json:"input"`
	Context string `json:"context"`
}

// mlExecResponse mirrors MLScore on the wire. Backend authors return
// {"verdict":"CLEAN|SUSPICIOUS|BLOCKED","confidence":0.x,
//  "model_version":"name@semver"}.
type mlExecResponse struct {
	Verdict      string  `json:"verdict"`
	Confidence   float64 `json:"confidence"`
	ModelVersion string  `json:"model_version"`
}

func (m *mlExec) Score(ctx context.Context, input, contextTag string) (*MLScore, error) {
	if m.cfg.BinaryPath == "" {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
	defer cancel()

	req, err := json.Marshal(mlExecRequest{Input: input, Context: contextTag})
	if err != nil {
		return nil, fmt.Errorf("ml backend: marshal: %w", err)
	}

	cmd := exec.CommandContext(cctx, m.cfg.BinaryPath, m.cfg.ExtraArgs...)
	cmd.Stdin = bytes.NewReader(req)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if cctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("ml backend: timeout after %s", m.cfg.Timeout)
		}
		return nil, fmt.Errorf("ml backend: exec: %w (stderr=%s)", err, strings.TrimSpace(stderr.String()))
	}

	var resp mlExecResponse
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &resp); err != nil {
		return nil, fmt.Errorf("ml backend: parse response: %w", err)
	}
	switch resp.Verdict {
	case "CLEAN", "SUSPICIOUS", "BLOCKED":
	default:
		return nil, fmt.Errorf("ml backend: invalid verdict %q", resp.Verdict)
	}
	return &MLScore{
		Confidence:   resp.Confidence,
		Verdict:      resp.Verdict,
		ModelVersion: resp.ModelVersion,
	}, nil
}

// MLBackendAdapter exposes an MLBackend through the legacy MLEnricher
// interface. Lets the existing Scanner.ScanWithML wiring stay
// untouched while the v1.0 backend ships behind the new contract.
type MLBackendAdapter struct{ B MLBackend }

func (a MLBackendAdapter) Score(ctx context.Context, input, ctxTag string) (*MLScore, error) {
	return a.B.Score(ctx, input, ctxTag)
}

func (a MLBackendAdapter) AlwaysScore() bool { return a.B.AlwaysScore() }
