// Code generated convenience getters for the hand-written proto messages.
// Mirrors the API protoc-gen-go would emit so client.go can call
// m.GetField() with nil-safe semantics.

package mlpb

// ── PromptScoreRequest ────────────────────────────────────────────

func (m *PromptScoreRequest) GetInput() string {
	if m == nil {
		return ""
	}
	return m.Input
}
func (m *PromptScoreRequest) GetContext() string {
	if m == nil {
		return ""
	}
	return m.Context
}
func (m *PromptScoreRequest) GetCorrelationId() string {
	if m == nil {
		return ""
	}
	return m.CorrelationId
}
func (m *PromptScoreRequest) GetTenant() string {
	if m == nil {
		return ""
	}
	return m.Tenant
}

// ── PhishingScoreRequest ──────────────────────────────────────────

func (m *PhishingScoreRequest) GetInput() string {
	if m == nil {
		return ""
	}
	return m.Input
}
func (m *PhishingScoreRequest) GetKind() string {
	if m == nil {
		return ""
	}
	return m.Kind
}
func (m *PhishingScoreRequest) GetCorrelationId() string {
	if m == nil {
		return ""
	}
	return m.CorrelationId
}
func (m *PhishingScoreRequest) GetTenant() string {
	if m == nil {
		return ""
	}
	return m.Tenant
}

// ── FeatureWeight ─────────────────────────────────────────────────

func (m *FeatureWeight) GetName() string {
	if m == nil {
		return ""
	}
	return m.Name
}
func (m *FeatureWeight) GetWeight() float64 {
	if m == nil {
		return 0
	}
	return m.Weight
}

// ── ScoreResponse ─────────────────────────────────────────────────

func (m *ScoreResponse) GetConfidence() float64 {
	if m == nil {
		return 0
	}
	return m.Confidence
}
func (m *ScoreResponse) GetVerdict() string {
	if m == nil {
		return ""
	}
	return m.Verdict
}
func (m *ScoreResponse) GetTopFeatures() []*FeatureWeight {
	if m == nil {
		return nil
	}
	return m.TopFeatures
}
func (m *ScoreResponse) GetLatencyMs() float64 {
	if m == nil {
		return 0
	}
	return m.LatencyMs
}
func (m *ScoreResponse) GetModelVersion() string {
	if m == nil {
		return ""
	}
	return m.ModelVersion
}
func (m *ScoreResponse) GetInputHash() string {
	if m == nil {
		return ""
	}
	return m.InputHash
}

// ── ModelInfoResponse ─────────────────────────────────────────────

func (m *ModelInfoResponse) GetName() string {
	if m == nil {
		return ""
	}
	return m.Name
}
func (m *ModelInfoResponse) GetVersion() string {
	if m == nil {
		return ""
	}
	return m.Version
}
func (m *ModelInfoResponse) GetTrainingSummary() string {
	if m == nil {
		return ""
	}
	return m.TrainingSummary
}
func (m *ModelInfoResponse) GetLoadedAt() int64 {
	if m == nil {
		return 0
	}
	return m.LoadedAt
}
func (m *ModelInfoResponse) GetBackend() string {
	if m == nil {
		return ""
	}
	return m.Backend
}
func (m *ModelInfoResponse) GetEvalMetricsJson() string {
	if m == nil {
		return ""
	}
	return m.EvalMetricsJson
}
