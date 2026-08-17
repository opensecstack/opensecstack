package mlpb

import (
	"math"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// ─── Reset / String / ProtoMessage smoke tests ──────────────────────

func TestReset_ZeroesMessages(t *testing.T) {
	psr := &PromptScoreRequest{Input: "x"}
	psr.Reset()
	if psr.Input != "" {
		t.Errorf("PromptScoreRequest.Reset() left Input = %q", psr.Input)
	}

	phr := &PhishingScoreRequest{Input: "x"}
	phr.Reset()
	if phr.Input != "" {
		t.Errorf("PhishingScoreRequest.Reset() left Input = %q", phr.Input)
	}

	msr := &MediaScoreRequest{FileHash: "x"}
	msr.Reset()
	if msr.FileHash != "" {
		t.Errorf("MediaScoreRequest.Reset() left FileHash = %q", msr.FileHash)
	}

	isr := &IdentityScoreRequest{ClaimType: "x"}
	isr.Reset()
	if isr.ClaimType != "" {
		t.Errorf("IdentityScoreRequest.Reset() left ClaimType = %q", isr.ClaimType)
	}

	asr := &AudioScoreRequest{SessionId: "x"}
	asr.Reset()
	if asr.SessionId != "" {
		t.Errorf("AudioScoreRequest.Reset() left SessionId = %q", asr.SessionId)
	}

	vfr := &VideoFrameRequest{SessionId: "x"}
	vfr.Reset()
	if vfr.SessionId != "" {
		t.Errorf("VideoFrameRequest.Reset() left SessionId = %q", vfr.SessionId)
	}

	vse := &VideoScoreEvent{SessionId: "x"}
	vse.Reset()
	if vse.SessionId != "" {
		t.Errorf("VideoScoreEvent.Reset() left SessionId = %q", vse.SessionId)
	}

	fw := &FeatureWeight{Name: "x"}
	fw.Reset()
	if fw.Name != "" {
		t.Errorf("FeatureWeight.Reset() left Name = %q", fw.Name)
	}

	sr := &ScoreResponse{Verdict: "x"}
	sr.Reset()
	if sr.Verdict != "" {
		t.Errorf("ScoreResponse.Reset() left Verdict = %q", sr.Verdict)
	}

	mireq := &ModelInfoRequest{}
	mireq.Reset()

	mir := &ModelInfoResponse{Name: "x"}
	mir.Reset()
	if mir.Name != "" {
		t.Errorf("ModelInfoResponse.Reset() left Name = %q", mir.Name)
	}
}

func TestString_ContainsKeyFields(t *testing.T) {
	cases := []struct {
		name string
		s    string
		want []string
	}{
		{"PromptScoreRequest", (&PromptScoreRequest{Context: "chat", CorrelationId: "c1", Tenant: "t1", Input: "hello"}).String(),
			[]string{"chat", "c1", "t1", "5"}},
		{"PhishingScoreRequest", (&PhishingScoreRequest{Kind: "url", CorrelationId: "c1", Tenant: "t1"}).String(),
			[]string{"url", "c1", "t1"}},
		{"MediaScoreRequest", (&MediaScoreRequest{FileHash: "h1", MimeType: "image/png", FileSize: 10, CorrelationId: "c1", Tenant: "t1"}).String(),
			[]string{"h1", "image/png", "c1", "t1"}},
		{"IdentityScoreRequest", (&IdentityScoreRequest{ClaimType: "passport", Context: "kyc", CorrelationId: "c1", Tenant: "t1"}).String(),
			[]string{"passport", "kyc", "c1", "t1"}},
		{"AudioScoreRequest", (&AudioScoreRequest{SessionId: "s1", VoiceDetected: true, CorrelationId: "c1", Tenant: "t1"}).String(),
			[]string{"s1", "true", "c1", "t1"}},
		{"VideoFrameRequest", (&VideoFrameRequest{SessionId: "s1", FrameSeq: 3, CorrelationId: "c1", Tenant: "t1"}).String(),
			[]string{"s1", "c1", "t1"}},
		{"VideoScoreEvent", (&VideoScoreEvent{SessionId: "s1", FrameSeq: 3, Verdict: "clean"}).String(),
			[]string{"s1", "clean"}},
		{"FeatureWeight", (&FeatureWeight{Name: "feat"}).String(), []string{"feat"}},
		{"ScoreResponse", (&ScoreResponse{Verdict: "malicious", ModelVersion: "v1"}).String(), []string{"malicious", "v1"}},
		{"ModelInfoRequest", (&ModelInfoRequest{}).String(), []string{"ModelInfoRequest"}},
		{"ModelInfoResponse", (&ModelInfoResponse{Name: "m1", Version: "1.0", Backend: "onnx"}).String(), []string{"m1", "1.0", "onnx"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, want := range c.want {
				if !strings.Contains(c.s, want) {
					t.Errorf("%s.String() = %q, want substring %q", c.name, c.s, want)
				}
			}
		})
	}
}

func TestProtoMessage_NoPanic(t *testing.T) {
	(&PromptScoreRequest{}).ProtoMessage()
	(&PhishingScoreRequest{}).ProtoMessage()
	(&MediaScoreRequest{}).ProtoMessage()
	(&IdentityScoreRequest{}).ProtoMessage()
	(&AudioScoreRequest{}).ProtoMessage()
	(&VideoFrameRequest{}).ProtoMessage()
	(&VideoScoreEvent{}).ProtoMessage()
	(&FeatureWeight{}).ProtoMessage()
	(&ScoreResponse{}).ProtoMessage()
	(&ModelInfoRequest{}).ProtoMessage()
	(&ModelInfoResponse{}).ProtoMessage()
}

// ─── Marshal/Unmarshal round trips ──────────────────────────────────

func TestRoundTrip_PromptScoreRequest(t *testing.T) {
	orig := &PromptScoreRequest{Input: "hello", Context: "chat", CorrelationId: "corr", Tenant: "t1"}
	data, err := orig.MarshalVT()
	if err != nil {
		t.Fatalf("MarshalVT: %v", err)
	}
	got := &PromptScoreRequest{}
	if err := got.UnmarshalVT(data); err != nil {
		t.Fatalf("UnmarshalVT: %v", err)
	}
	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, orig)
	}
}

func TestRoundTrip_PhishingScoreRequest(t *testing.T) {
	orig := &PhishingScoreRequest{Input: "click here", Kind: "url", CorrelationId: "corr", Tenant: "t1"}
	data, err := orig.MarshalVT()
	if err != nil {
		t.Fatalf("MarshalVT: %v", err)
	}
	got := &PhishingScoreRequest{}
	if err := got.UnmarshalVT(data); err != nil {
		t.Fatalf("UnmarshalVT: %v", err)
	}
	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, orig)
	}
}

func TestRoundTrip_MediaScoreRequest(t *testing.T) {
	orig := &MediaScoreRequest{
		FileHash: "abc123", MimeType: "image/jpeg", FileSize: 204800,
		HasC2PaManifest: true, C2PaSignatureValid: false,
		CorrelationId: "corr", Tenant: "t1",
	}
	data, err := orig.MarshalVT()
	if err != nil {
		t.Fatalf("MarshalVT: %v", err)
	}
	got := &MediaScoreRequest{}
	if err := got.UnmarshalVT(data); err != nil {
		t.Fatalf("UnmarshalVT: %v", err)
	}
	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, orig)
	}

	// Explicit false-boolean case: zero-value message must not corrupt
	// bool fields (they are only appended to the wire when true).
	orig2 := &MediaScoreRequest{FileHash: "h", HasC2PaManifest: false, C2PaSignatureValid: false}
	data2, err := orig2.MarshalVT()
	if err != nil {
		t.Fatalf("MarshalVT: %v", err)
	}
	got2 := &MediaScoreRequest{}
	if err := got2.UnmarshalVT(data2); err != nil {
		t.Fatalf("UnmarshalVT: %v", err)
	}
	if got2.HasC2PaManifest || got2.C2PaSignatureValid {
		t.Fatalf("expected false booleans to stay false, got %+v", got2)
	}
}

func TestRoundTrip_IdentityScoreRequest(t *testing.T) {
	orig := &IdentityScoreRequest{
		ClaimType: "passport", Context: "kyc-flow", NameTokenCount: 4,
		EmailDomainIsDisposable: true, IdFormatValid: true, IssuerCountry: "AL",
		HasDob: true, ReplayCount: 7, CorrelationId: "corr", Tenant: "t1",
	}
	data, err := orig.MarshalVT()
	if err != nil {
		t.Fatalf("MarshalVT: %v", err)
	}
	got := &IdentityScoreRequest{}
	if err := got.UnmarshalVT(data); err != nil {
		t.Fatalf("UnmarshalVT: %v", err)
	}
	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, orig)
	}
}

func TestRoundTrip_AudioScoreRequest(t *testing.T) {
	orig := &AudioScoreRequest{
		SessionId: "sess1", MfccHash: []byte{0x01, 0x02, 0x03}, SpectralHash: []byte{0xAA, 0xBB},
		DurationMs: 1234.5, VoiceDetected: true, CorrelationId: "corr", Tenant: "t1",
	}
	data, err := orig.MarshalVT()
	if err != nil {
		t.Fatalf("MarshalVT: %v", err)
	}
	got := &AudioScoreRequest{}
	if err := got.UnmarshalVT(data); err != nil {
		t.Fatalf("UnmarshalVT: %v", err)
	}
	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, orig)
	}

	// Empty byte slices are omitted on the wire; verify decode leaves nils.
	empty := &AudioScoreRequest{SessionId: "s"}
	data2, err := empty.MarshalVT()
	if err != nil {
		t.Fatalf("MarshalVT: %v", err)
	}
	got2 := &AudioScoreRequest{}
	if err := got2.UnmarshalVT(data2); err != nil {
		t.Fatalf("UnmarshalVT: %v", err)
	}
	if got2.MfccHash != nil || got2.SpectralHash != nil {
		t.Fatalf("expected nil byte slices, got %+v", got2)
	}
}

func TestRoundTrip_VideoFrameRequest(t *testing.T) {
	orig := &VideoFrameRequest{
		SessionId: "sess1", FrameSeq: 42, FrameTsMs: 999999, FeatureVector: []byte{1, 2, 3, 4},
		FaceDetected: true, CorrelationId: "corr", Tenant: "t1",
	}
	data, err := orig.MarshalVT()
	if err != nil {
		t.Fatalf("MarshalVT: %v", err)
	}
	got := &VideoFrameRequest{}
	if err := got.UnmarshalVT(data); err != nil {
		t.Fatalf("UnmarshalVT: %v", err)
	}
	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, orig)
	}
}

func TestRoundTrip_VideoScoreEvent(t *testing.T) {
	orig := &VideoScoreEvent{
		SessionId: "sess1", FrameSeq: 42, Confidence: 0.87, Verdict: "deepfake",
		LatencyMs: 15.3, ModelVersion: "v4",
	}
	data, err := orig.MarshalVT()
	if err != nil {
		t.Fatalf("MarshalVT: %v", err)
	}
	got := &VideoScoreEvent{}
	if err := got.UnmarshalVT(data); err != nil {
		t.Fatalf("UnmarshalVT: %v", err)
	}
	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, orig)
	}
}

func TestRoundTrip_FeatureWeight(t *testing.T) {
	orig := &FeatureWeight{Name: "urgency_score", Weight: -3.14}
	data, err := orig.MarshalVT()
	if err != nil {
		t.Fatalf("MarshalVT: %v", err)
	}
	got := &FeatureWeight{}
	if err := got.UnmarshalVT(data); err != nil {
		t.Fatalf("UnmarshalVT: %v", err)
	}
	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, orig)
	}
}

func TestRoundTrip_ScoreResponse_WithNestedFeatures(t *testing.T) {
	orig := &ScoreResponse{
		Confidence: 0.95,
		Verdict:    "malicious",
		TopFeatures: []*FeatureWeight{
			{Name: "f1", Weight: 0.5},
			{Name: "f2", Weight: -0.2},
		},
		LatencyMs:    22.1,
		ModelVersion: "v5",
		InputHash:    "sha256:abc",
	}
	data, err := orig.MarshalVT()
	if err != nil {
		t.Fatalf("MarshalVT: %v", err)
	}
	got := &ScoreResponse{}
	if err := got.UnmarshalVT(data); err != nil {
		t.Fatalf("UnmarshalVT: %v", err)
	}
	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, orig)
	}

	// No nested features: TopFeatures must decode back to nil, not [].
	orig2 := &ScoreResponse{Verdict: "clean"}
	data2, err := orig2.MarshalVT()
	if err != nil {
		t.Fatalf("MarshalVT: %v", err)
	}
	got2 := &ScoreResponse{}
	if err := got2.UnmarshalVT(data2); err != nil {
		t.Fatalf("UnmarshalVT: %v", err)
	}
	if got2.TopFeatures != nil {
		t.Fatalf("expected nil TopFeatures, got %+v", got2.TopFeatures)
	}
}

func TestRoundTrip_ModelInfoRequest(t *testing.T) {
	orig := &ModelInfoRequest{}
	data, err := orig.MarshalVT()
	if err != nil {
		t.Fatalf("MarshalVT: %v", err)
	}
	if data != nil {
		t.Fatalf("expected nil bytes for empty request, got %v", data)
	}
	got := &ModelInfoRequest{}
	if err := got.UnmarshalVT(data); err != nil {
		t.Fatalf("UnmarshalVT: %v", err)
	}

	// UnmarshalVT must also tolerate unknown fields on an otherwise
	// empty message (forward compatibility with server additions).
	var extra []byte
	extra = protowire.AppendTag(extra, 9, protowire.VarintType)
	extra = protowire.AppendVarint(extra, 123)
	if err := got.UnmarshalVT(extra); err != nil {
		t.Fatalf("UnmarshalVT with unknown field: %v", err)
	}
}

func TestRoundTrip_ModelInfoResponse(t *testing.T) {
	orig := &ModelInfoResponse{
		Name: "phishing-detector", Version: "2.3.1", TrainingSummary: "trained on 1M samples",
		LoadedAt: 1712345678, Backend: "onnxruntime", EvalMetricsJson: `{"precision":0.92,"recall":0.88}`,
	}
	data, err := orig.MarshalVT()
	if err != nil {
		t.Fatalf("MarshalVT: %v", err)
	}
	got := &ModelInfoResponse{}
	if err := got.UnmarshalVT(data); err != nil {
		t.Fatalf("UnmarshalVT: %v", err)
	}
	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, orig)
	}
}

// TestUnmarshalVT_SkipsUnknownFields verifies forward-compatibility: an
// unrecognised field number must be skipped via ConsumeFieldValue without
// corrupting the fields that follow it.
func TestUnmarshalVT_SkipsUnknownFields(t *testing.T) {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, "known-input")
	// unknown field 99, varint type
	b = protowire.AppendTag(b, 99, protowire.VarintType)
	b = protowire.AppendVarint(b, 777)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, "known-context")

	got := &PromptScoreRequest{}
	if err := got.UnmarshalVT(b); err != nil {
		t.Fatalf("UnmarshalVT: %v", err)
	}
	if got.Input != "known-input" || got.Context != "known-context" {
		t.Fatalf("unknown field corrupted decode: %+v", got)
	}
}

// TestUnmarshalVT_MalformedData verifies malformed/truncated wire bytes
// surface an error rather than panicking or silently succeeding.
func TestUnmarshalVT_MalformedData(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"truncated tag", []byte{0xFF}},
		{"truncated varint", []byte{0x08, 0xFF}},
		{"truncated length-delimited", []byte{0x0A, 0x05, 'a', 'b'}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &PromptScoreRequest{}
			if err := m.UnmarshalVT(c.data); err == nil {
				t.Errorf("expected error for %s, got nil", c.name)
			}
		})
	}
}

func TestUnmarshalVT_MalformedNested(t *testing.T) {
	// ScoreResponse field 3 (TopFeatures) expects a length-delimited
	// FeatureWeight submessage; feed it corrupt bytes.
	var b []byte
	b = protowire.AppendTag(b, 3, protowire.BytesType)
	b = protowire.AppendBytes(b, []byte{0xFF, 0xFF, 0xFF})

	got := &ScoreResponse{}
	if err := got.UnmarshalVT(b); err == nil {
		t.Fatal("expected error decoding malformed nested FeatureWeight")
	}
}

// ─── wire-format helper unit tests ──────────────────────────────────

func TestAppendString_OmitsEmpty(t *testing.T) {
	if got := appendString(nil, 1, ""); got != nil {
		t.Errorf("appendString with empty string = %v, want nil", got)
	}
	got := appendString(nil, 1, "x")
	if len(got) == 0 {
		t.Error("appendString with non-empty string produced no bytes")
	}
}

func TestAppendVarint_OmitsZero(t *testing.T) {
	if got := appendVarint(nil, 1, 0); got != nil {
		t.Errorf("appendVarint with 0 = %v, want nil", got)
	}
	got := appendVarint(nil, 1, 5)
	if len(got) == 0 {
		t.Error("appendVarint with non-zero produced no bytes")
	}
}

func TestAppendDouble_OmitsZero(t *testing.T) {
	if got := appendDouble(nil, 1, 0); got != nil {
		t.Errorf("appendDouble with 0 = %v, want nil", got)
	}
	got := appendDouble(nil, 1, 1.5)
	if len(got) == 0 {
		t.Error("appendDouble with non-zero produced no bytes")
	}
}

func TestAppendFloat32_OmitsZero(t *testing.T) {
	if got := appendFloat32(nil, 1, 0); got != nil {
		t.Errorf("appendFloat32 with 0 = %v, want nil", got)
	}
	got := appendFloat32(nil, 1, 2.5)
	if len(got) == 0 {
		t.Error("appendFloat32 with non-zero produced no bytes")
	}
}

func TestAppendBytes_AlwaysAppends(t *testing.T) {
	got := appendBytes(nil, 1, []byte{})
	if len(got) == 0 {
		t.Error("appendBytes with empty slice should still write a tag")
	}
	got2 := appendBytes(nil, 1, []byte{1, 2, 3})
	if len(got2) == 0 {
		t.Error("appendBytes with data produced no bytes")
	}
}

func TestConsumeString_WrongType(t *testing.T) {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, 42)
	// Strip the tag before calling consumeString directly (it operates on
	// the value portion only).
	_, typ, n := protowire.ConsumeTag(b)
	rest := b[n:]
	s, consumed := consumeString(rest, typ)
	if s != "" {
		t.Errorf("consumeString with wrong type = %q, want \"\"", s)
	}
	if consumed <= 0 {
		t.Error("consumeString should still consume the mismatched field value")
	}
}

func TestConsumeVarint_WrongType(t *testing.T) {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, "not-a-varint")
	_, typ, n := protowire.ConsumeTag(b)
	rest := b[n:]
	v, consumed := consumeVarint(rest, typ)
	if v != 0 {
		t.Errorf("consumeVarint with wrong type = %d, want 0", v)
	}
	if consumed <= 0 {
		t.Error("consumeVarint should still consume the mismatched field value")
	}
}

func TestConsumeDouble_WrongType(t *testing.T) {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, 5)
	_, typ, n := protowire.ConsumeTag(b)
	rest := b[n:]
	f, consumed := consumeDouble(rest, typ)
	if f != 0 {
		t.Errorf("consumeDouble with wrong type = %v, want 0", f)
	}
	if consumed <= 0 {
		t.Error("consumeDouble should still consume the mismatched field value")
	}
}

func TestConsumeFloat32_WrongType(t *testing.T) {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, 5)
	_, typ, n := protowire.ConsumeTag(b)
	rest := b[n:]
	f, consumed := consumeFloat32(rest, typ)
	if f != 0 {
		t.Errorf("consumeFloat32 with wrong type = %v, want 0", f)
	}
	if consumed <= 0 {
		t.Error("consumeFloat32 should still consume the mismatched field value")
	}
}

func TestConsumeBytes_WrongType(t *testing.T) {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, 5)
	_, typ, n := protowire.ConsumeTag(b)
	rest := b[n:]
	v, consumed := consumeBytes(rest, typ)
	if v != nil {
		t.Errorf("consumeBytes with wrong type = %v, want nil", v)
	}
	if consumed <= 0 {
		t.Error("consumeBytes should still consume the mismatched field value")
	}
}

func TestConsumeBytes_CopiesData(t *testing.T) {
	orig := []byte{1, 2, 3}
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, orig)
	_, typ, n := protowire.ConsumeTag(b)
	rest := b[n:]
	v, _ := consumeBytes(rest, typ)
	if !reflect.DeepEqual(v, orig) {
		t.Fatalf("consumeBytes = %v, want %v", v, orig)
	}
	// Mutating the source buffer must not affect the returned copy.
	rest[0] = 0xFF
	if v[0] == 0xFF {
		t.Error("consumeBytes did not return an independent copy")
	}
}

func TestConsumeMessage_WrongType(t *testing.T) {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, 5)
	_, typ, n := protowire.ConsumeTag(b)
	rest := b[n:]
	v, consumed := consumeMessage(rest, typ)
	if v != nil {
		t.Errorf("consumeMessage with wrong type = %v, want nil", v)
	}
	if consumed <= 0 {
		t.Error("consumeMessage should still consume the mismatched field value")
	}
}

func TestMathFloatHelpers_RoundTrip(t *testing.T) {
	f64 := 3.14159265358979
	if got := math_Float64frombits(math_Float64bits(f64)); got != f64 {
		t.Errorf("math_Float64 round trip = %v, want %v", got, f64)
	}
	f32 := float32(2.71828)
	if got := math_Float32frombits(math_Float32bits(f32)); got != f32 {
		t.Errorf("math_Float32 round trip = %v, want %v", got, f32)
	}
	// Sanity: these are thin wrappers over math.Float*bits.
	if math_Float64bits(1.0) != math.Float64bits(1.0) {
		t.Error("math_Float64bits diverges from math.Float64bits")
	}
	if math_Float32bits(1.0) != math.Float32bits(1.0) {
		t.Error("math_Float32bits diverges from math.Float32bits")
	}
}
