package mlpb

import (
	"reflect"
	"testing"
)

// TestGetters_NilSafe verifies every generated Get* accessor returns the
// message's zero value when called on a nil receiver — the core contract
// client.go relies on (mirrors protoc-gen-go's nil-safe getter semantics).
func TestGetters_NilSafe(t *testing.T) {
	var (
		psr *PromptScoreRequest
		phr *PhishingScoreRequest
		fw  *FeatureWeight
		sr  *ScoreResponse
		mir *ModelInfoResponse
		msr *MediaScoreRequest
		isr *IdentityScoreRequest
		asr *AudioScoreRequest
		vfr *VideoFrameRequest
		vse *VideoScoreEvent
	)

	if got := psr.GetInput(); got != "" {
		t.Errorf("PromptScoreRequest(nil).GetInput() = %q, want \"\"", got)
	}
	if got := psr.GetContext(); got != "" {
		t.Errorf("PromptScoreRequest(nil).GetContext() = %q, want \"\"", got)
	}
	if got := psr.GetCorrelationId(); got != "" {
		t.Errorf("PromptScoreRequest(nil).GetCorrelationId() = %q, want \"\"", got)
	}
	if got := psr.GetTenant(); got != "" {
		t.Errorf("PromptScoreRequest(nil).GetTenant() = %q, want \"\"", got)
	}

	if got := phr.GetInput(); got != "" {
		t.Errorf("PhishingScoreRequest(nil).GetInput() = %q, want \"\"", got)
	}
	if got := phr.GetKind(); got != "" {
		t.Errorf("PhishingScoreRequest(nil).GetKind() = %q, want \"\"", got)
	}
	if got := phr.GetCorrelationId(); got != "" {
		t.Errorf("PhishingScoreRequest(nil).GetCorrelationId() = %q, want \"\"", got)
	}
	if got := phr.GetTenant(); got != "" {
		t.Errorf("PhishingScoreRequest(nil).GetTenant() = %q, want \"\"", got)
	}

	if got := fw.GetName(); got != "" {
		t.Errorf("FeatureWeight(nil).GetName() = %q, want \"\"", got)
	}
	if got := fw.GetWeight(); got != 0 {
		t.Errorf("FeatureWeight(nil).GetWeight() = %v, want 0", got)
	}

	if got := sr.GetConfidence(); got != 0 {
		t.Errorf("ScoreResponse(nil).GetConfidence() = %v, want 0", got)
	}
	if got := sr.GetVerdict(); got != "" {
		t.Errorf("ScoreResponse(nil).GetVerdict() = %q, want \"\"", got)
	}
	if got := sr.GetTopFeatures(); got != nil {
		t.Errorf("ScoreResponse(nil).GetTopFeatures() = %v, want nil", got)
	}
	if got := sr.GetLatencyMs(); got != 0 {
		t.Errorf("ScoreResponse(nil).GetLatencyMs() = %v, want 0", got)
	}
	if got := sr.GetModelVersion(); got != "" {
		t.Errorf("ScoreResponse(nil).GetModelVersion() = %q, want \"\"", got)
	}
	if got := sr.GetInputHash(); got != "" {
		t.Errorf("ScoreResponse(nil).GetInputHash() = %q, want \"\"", got)
	}

	if got := mir.GetName(); got != "" {
		t.Errorf("ModelInfoResponse(nil).GetName() = %q, want \"\"", got)
	}
	if got := mir.GetVersion(); got != "" {
		t.Errorf("ModelInfoResponse(nil).GetVersion() = %q, want \"\"", got)
	}
	if got := mir.GetTrainingSummary(); got != "" {
		t.Errorf("ModelInfoResponse(nil).GetTrainingSummary() = %q, want \"\"", got)
	}
	if got := mir.GetLoadedAt(); got != 0 {
		t.Errorf("ModelInfoResponse(nil).GetLoadedAt() = %v, want 0", got)
	}
	if got := mir.GetBackend(); got != "" {
		t.Errorf("ModelInfoResponse(nil).GetBackend() = %q, want \"\"", got)
	}
	if got := mir.GetEvalMetricsJson(); got != "" {
		t.Errorf("ModelInfoResponse(nil).GetEvalMetricsJson() = %q, want \"\"", got)
	}

	if got := msr.GetFileHash(); got != "" {
		t.Errorf("MediaScoreRequest(nil).GetFileHash() = %q, want \"\"", got)
	}
	if got := msr.GetMimeType(); got != "" {
		t.Errorf("MediaScoreRequest(nil).GetMimeType() = %q, want \"\"", got)
	}
	if got := msr.GetFileSize(); got != 0 {
		t.Errorf("MediaScoreRequest(nil).GetFileSize() = %v, want 0", got)
	}
	if got := msr.GetHasC2PaManifest(); got != false {
		t.Errorf("MediaScoreRequest(nil).GetHasC2PaManifest() = %v, want false", got)
	}
	if got := msr.GetC2PaSignatureValid(); got != false {
		t.Errorf("MediaScoreRequest(nil).GetC2PaSignatureValid() = %v, want false", got)
	}
	if got := msr.GetCorrelationId(); got != "" {
		t.Errorf("MediaScoreRequest(nil).GetCorrelationId() = %q, want \"\"", got)
	}
	if got := msr.GetTenant(); got != "" {
		t.Errorf("MediaScoreRequest(nil).GetTenant() = %q, want \"\"", got)
	}

	if got := isr.GetClaimType(); got != "" {
		t.Errorf("IdentityScoreRequest(nil).GetClaimType() = %q, want \"\"", got)
	}
	if got := isr.GetContext(); got != "" {
		t.Errorf("IdentityScoreRequest(nil).GetContext() = %q, want \"\"", got)
	}
	if got := isr.GetNameTokenCount(); got != 0 {
		t.Errorf("IdentityScoreRequest(nil).GetNameTokenCount() = %v, want 0", got)
	}
	if got := isr.GetEmailDomainIsDisposable(); got != false {
		t.Errorf("IdentityScoreRequest(nil).GetEmailDomainIsDisposable() = %v, want false", got)
	}
	if got := isr.GetIdFormatValid(); got != false {
		t.Errorf("IdentityScoreRequest(nil).GetIdFormatValid() = %v, want false", got)
	}
	if got := isr.GetIssuerCountry(); got != "" {
		t.Errorf("IdentityScoreRequest(nil).GetIssuerCountry() = %q, want \"\"", got)
	}
	if got := isr.GetHasDob(); got != false {
		t.Errorf("IdentityScoreRequest(nil).GetHasDob() = %v, want false", got)
	}
	if got := isr.GetReplayCount(); got != 0 {
		t.Errorf("IdentityScoreRequest(nil).GetReplayCount() = %v, want 0", got)
	}
	if got := isr.GetCorrelationId(); got != "" {
		t.Errorf("IdentityScoreRequest(nil).GetCorrelationId() = %q, want \"\"", got)
	}
	if got := isr.GetTenant(); got != "" {
		t.Errorf("IdentityScoreRequest(nil).GetTenant() = %q, want \"\"", got)
	}

	if got := asr.GetSessionId(); got != "" {
		t.Errorf("AudioScoreRequest(nil).GetSessionId() = %q, want \"\"", got)
	}
	if got := asr.GetMfccHash(); got != nil {
		t.Errorf("AudioScoreRequest(nil).GetMfccHash() = %v, want nil", got)
	}
	if got := asr.GetSpectralHash(); got != nil {
		t.Errorf("AudioScoreRequest(nil).GetSpectralHash() = %v, want nil", got)
	}
	if got := asr.GetDurationMs(); got != 0 {
		t.Errorf("AudioScoreRequest(nil).GetDurationMs() = %v, want 0", got)
	}
	if got := asr.GetVoiceDetected(); got != false {
		t.Errorf("AudioScoreRequest(nil).GetVoiceDetected() = %v, want false", got)
	}
	if got := asr.GetCorrelationId(); got != "" {
		t.Errorf("AudioScoreRequest(nil).GetCorrelationId() = %q, want \"\"", got)
	}
	if got := asr.GetTenant(); got != "" {
		t.Errorf("AudioScoreRequest(nil).GetTenant() = %q, want \"\"", got)
	}

	if got := vfr.GetSessionId(); got != "" {
		t.Errorf("VideoFrameRequest(nil).GetSessionId() = %q, want \"\"", got)
	}
	if got := vfr.GetFrameSeq(); got != 0 {
		t.Errorf("VideoFrameRequest(nil).GetFrameSeq() = %v, want 0", got)
	}
	if got := vfr.GetFrameTsMs(); got != 0 {
		t.Errorf("VideoFrameRequest(nil).GetFrameTsMs() = %v, want 0", got)
	}
	if got := vfr.GetFeatureVector(); got != nil {
		t.Errorf("VideoFrameRequest(nil).GetFeatureVector() = %v, want nil", got)
	}
	if got := vfr.GetFaceDetected(); got != false {
		t.Errorf("VideoFrameRequest(nil).GetFaceDetected() = %v, want false", got)
	}
	if got := vfr.GetCorrelationId(); got != "" {
		t.Errorf("VideoFrameRequest(nil).GetCorrelationId() = %q, want \"\"", got)
	}
	if got := vfr.GetTenant(); got != "" {
		t.Errorf("VideoFrameRequest(nil).GetTenant() = %q, want \"\"", got)
	}

	if got := vse.GetSessionId(); got != "" {
		t.Errorf("VideoScoreEvent(nil).GetSessionId() = %q, want \"\"", got)
	}
	if got := vse.GetFrameSeq(); got != 0 {
		t.Errorf("VideoScoreEvent(nil).GetFrameSeq() = %v, want 0", got)
	}
	if got := vse.GetConfidence(); got != 0 {
		t.Errorf("VideoScoreEvent(nil).GetConfidence() = %v, want 0", got)
	}
	if got := vse.GetVerdict(); got != "" {
		t.Errorf("VideoScoreEvent(nil).GetVerdict() = %q, want \"\"", got)
	}
	if got := vse.GetLatencyMs(); got != 0 {
		t.Errorf("VideoScoreEvent(nil).GetLatencyMs() = %v, want 0", got)
	}
	if got := vse.GetModelVersion(); got != "" {
		t.Errorf("VideoScoreEvent(nil).GetModelVersion() = %q, want \"\"", got)
	}
}

// TestGetters_Populated verifies every accessor returns the exact field
// value set on a populated receiver — guards against copy/paste mistakes
// that return the wrong field.
func TestGetters_Populated(t *testing.T) {
	psr := &PromptScoreRequest{Input: "in", Context: "ctx", CorrelationId: "corr", Tenant: "ten"}
	if psr.GetInput() != "in" || psr.GetContext() != "ctx" || psr.GetCorrelationId() != "corr" || psr.GetTenant() != "ten" {
		t.Errorf("PromptScoreRequest getters mismatch: %+v", psr)
	}

	phr := &PhishingScoreRequest{Input: "in", Kind: "url", CorrelationId: "corr", Tenant: "ten"}
	if phr.GetInput() != "in" || phr.GetKind() != "url" || phr.GetCorrelationId() != "corr" || phr.GetTenant() != "ten" {
		t.Errorf("PhishingScoreRequest getters mismatch: %+v", phr)
	}

	fw := &FeatureWeight{Name: "feat", Weight: 0.75}
	if fw.GetName() != "feat" || fw.GetWeight() != 0.75 {
		t.Errorf("FeatureWeight getters mismatch: %+v", fw)
	}

	tf := []*FeatureWeight{{Name: "a", Weight: 1}}
	sr := &ScoreResponse{
		Confidence:   0.9,
		Verdict:      "malicious",
		TopFeatures:  tf,
		LatencyMs:    12.5,
		ModelVersion: "v3",
		InputHash:    "hash",
	}
	if sr.GetConfidence() != 0.9 || sr.GetVerdict() != "malicious" ||
		!reflect.DeepEqual(sr.GetTopFeatures(), tf) || sr.GetLatencyMs() != 12.5 ||
		sr.GetModelVersion() != "v3" || sr.GetInputHash() != "hash" {
		t.Errorf("ScoreResponse getters mismatch: %+v", sr)
	}

	mir := &ModelInfoResponse{
		Name: "model", Version: "1.0", TrainingSummary: "summary",
		LoadedAt: 42, Backend: "onnx", EvalMetricsJson: `{"f1":0.9}`,
	}
	if mir.GetName() != "model" || mir.GetVersion() != "1.0" || mir.GetTrainingSummary() != "summary" ||
		mir.GetLoadedAt() != 42 || mir.GetBackend() != "onnx" || mir.GetEvalMetricsJson() != `{"f1":0.9}` {
		t.Errorf("ModelInfoResponse getters mismatch: %+v", mir)
	}

	msr := &MediaScoreRequest{
		FileHash: "h", MimeType: "image/png", FileSize: 1024,
		HasC2PaManifest: true, C2PaSignatureValid: true,
		CorrelationId: "corr", Tenant: "ten",
	}
	if msr.GetFileHash() != "h" || msr.GetMimeType() != "image/png" || msr.GetFileSize() != 1024 ||
		!msr.GetHasC2PaManifest() || !msr.GetC2PaSignatureValid() ||
		msr.GetCorrelationId() != "corr" || msr.GetTenant() != "ten" {
		t.Errorf("MediaScoreRequest getters mismatch: %+v", msr)
	}

	isr := &IdentityScoreRequest{
		ClaimType: "passport", Context: "kyc", NameTokenCount: 3,
		EmailDomainIsDisposable: true, IdFormatValid: true, IssuerCountry: "AL",
		HasDob: true, ReplayCount: 2, CorrelationId: "corr", Tenant: "ten",
	}
	if isr.GetClaimType() != "passport" || isr.GetContext() != "kyc" || isr.GetNameTokenCount() != 3 ||
		!isr.GetEmailDomainIsDisposable() || !isr.GetIdFormatValid() || isr.GetIssuerCountry() != "AL" ||
		!isr.GetHasDob() || isr.GetReplayCount() != 2 || isr.GetCorrelationId() != "corr" || isr.GetTenant() != "ten" {
		t.Errorf("IdentityScoreRequest getters mismatch: %+v", isr)
	}

	asr := &AudioScoreRequest{
		SessionId: "sess", MfccHash: []byte{1, 2}, SpectralHash: []byte{3, 4},
		DurationMs: 250.5, VoiceDetected: true, CorrelationId: "corr", Tenant: "ten",
	}
	if asr.GetSessionId() != "sess" || !reflect.DeepEqual(asr.GetMfccHash(), []byte{1, 2}) ||
		!reflect.DeepEqual(asr.GetSpectralHash(), []byte{3, 4}) || asr.GetDurationMs() != 250.5 ||
		!asr.GetVoiceDetected() || asr.GetCorrelationId() != "corr" || asr.GetTenant() != "ten" {
		t.Errorf("AudioScoreRequest getters mismatch: %+v", asr)
	}

	vfr := &VideoFrameRequest{
		SessionId: "sess", FrameSeq: 7, FrameTsMs: 1000, FeatureVector: []byte{9, 9},
		FaceDetected: true, CorrelationId: "corr", Tenant: "ten",
	}
	if vfr.GetSessionId() != "sess" || vfr.GetFrameSeq() != 7 || vfr.GetFrameTsMs() != 1000 ||
		!reflect.DeepEqual(vfr.GetFeatureVector(), []byte{9, 9}) || !vfr.GetFaceDetected() ||
		vfr.GetCorrelationId() != "corr" || vfr.GetTenant() != "ten" {
		t.Errorf("VideoFrameRequest getters mismatch: %+v", vfr)
	}

	vse := &VideoScoreEvent{
		SessionId: "sess", FrameSeq: 5, Confidence: 0.6, Verdict: "clean",
		LatencyMs: 3.3, ModelVersion: "v2",
	}
	if vse.GetSessionId() != "sess" || vse.GetFrameSeq() != 5 || vse.GetConfidence() != 0.6 ||
		vse.GetVerdict() != "clean" || vse.GetLatencyMs() != 3.3 || vse.GetModelVersion() != "v2" {
		t.Errorf("VideoScoreEvent getters mismatch: %+v", vse)
	}
}
