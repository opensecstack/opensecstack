package prompt

// EngineConfig is the v1.0 startup contract. Wiring code (cmd/server)
// passes one of these to NewEngine instead of building the Scanner
// piecemeal — this keeps the production path consistent with what the
// tests exercise.
type EngineConfig struct {
	RulePackPath   string
	CleanThreshold float64
	BlockThreshold float64
	MaxInputBytes  int
	// Heuristics defaults to DefaultHeuristicLimits when zero-valued.
	Heuristics HeuristicLimits
}

// NewEngine builds the production Scanner. When RulePackPath is empty
// or the file fails to load, NewEngine falls back to DefaultLibrary
// and returns the load error alongside the working scanner so the
// caller can warn-log without blocking startup.
func NewEngine(cfg EngineConfig) (*Scanner, error) {
	patterns, loadErr := LoadRulePack(cfg.RulePackPath)
	if loadErr != nil || len(patterns) == 0 {
		patterns = DefaultLibrary
	}
	s := NewScanner(patterns, cfg.CleanThreshold, cfg.BlockThreshold, cfg.MaxInputBytes)
	lim := cfg.Heuristics
	if lim == (HeuristicLimits{}) {
		lim = DefaultHeuristicLimits
	}
	s.EnableHeuristics(lim)
	return s, loadErr
}
