package prompt

import (
	"context"
	"testing"
	"time"
)

func TestMLExec_DisabledByEmptyPath(t *testing.T) {
	b := NewMLExec(MLExecConfig{BinaryPath: "", Timeout: time.Second})
	got, err := b.Score(context.Background(), "anything", "user_chat_input")
	if err != nil {
		t.Fatalf("disabled backend must not error: %v", err)
	}
	if got != nil {
		t.Fatalf("disabled backend must return nil score, got %+v", got)
	}
	if b.AlwaysScore() {
		t.Fatalf("default AlwaysScore must be false")
	}
}

func TestMLExec_AdapterImplementsEnricher(t *testing.T) {
	var _ MLEnricher = MLBackendAdapter{B: NewMLExec(MLExecConfig{})}
}
