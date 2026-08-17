package mlpb

import "testing"

func TestCodec_Name(t *testing.T) {
	if got := (Codec{}).Name(); got != CodecName {
		t.Fatalf("Name() = %q, want %q", got, CodecName)
	}
	if CodecName != "proto" {
		t.Fatalf("CodecName = %q, want %q", CodecName, "proto")
	}
}

func TestCodec_MarshalUnmarshal_RoundTrip(t *testing.T) {
	c := Codec{}
	orig := &PromptScoreRequest{
		Input:         "hello world",
		Context:       "user_chat_input",
		CorrelationId: "corr-1",
		Tenant:        "tenant-a",
	}
	data, err := c.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal err: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("Marshal returned empty bytes for non-empty message")
	}

	got := &PromptScoreRequest{}
	if err := c.Unmarshal(data, got); err != nil {
		t.Fatalf("Unmarshal err: %v", err)
	}
	if got.Input != orig.Input || got.Context != orig.Context ||
		got.CorrelationId != orig.CorrelationId || got.Tenant != orig.Tenant {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, orig)
	}
}

func TestCodec_Marshal_RejectsNonVTMessage(t *testing.T) {
	c := Codec{}
	_, err := c.Marshal("not a vtMessage")
	if err == nil {
		t.Fatal("expected error marshalling a non-vtMessage value")
	}
}

func TestCodec_Unmarshal_RejectsNonVTMessage(t *testing.T) {
	c := Codec{}
	var target string
	err := c.Unmarshal([]byte("data"), &target)
	if err == nil {
		t.Fatal("expected error unmarshaling into a non-vtMessage value")
	}
}
