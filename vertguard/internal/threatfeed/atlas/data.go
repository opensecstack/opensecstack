// Package atlas provides the embedded initial MITRE ATLAS mapping set.
//
// STATUS: Phase 4.1 initial. A curated subset of ATLAS techniques
// that matter most for Module 3 (Prompt Injection) + Module 4 (Feed).
// Full ATLAS sync (weekly pull from atlas.mitre.org) is tracked as VG-006.
//
// Reference: https://atlas.mitre.org/
package atlas

// Technique is the canonical in-memory ATLAS technique record.
type Technique struct {
	ID          string
	Name        string
	Description string
	TacticID    string
	TacticName  string
	URL         string
}

// Tactics covered by the embedded dataset.
const (
	TacticExecution       = "AML.TA0005"
	TacticDiscovery       = "AML.TA0010"
	TacticCollection      = "AML.TA0011"
	TacticExfiltration    = "AML.TA0013"
	TacticDefenseEvasion  = "AML.TA0008"
	TacticMLAttackStaging = "AML.TA0012"
)

// Initial returns the curated subset of ATLAS techniques shipped
// with v0.1.0-alpha.0. Expanded via VG-006 full sync.
func Initial() []Technique {
	return []Technique{
		{
			ID: "AML.T0051", Name: "LLM Prompt Injection",
			Description: "Adversarial prompt input that overrides or supplements the original prompt, altering the LLM's behaviour.",
			TacticID:    TacticExecution, TacticName: "Execution",
			URL: "https://atlas.mitre.org/techniques/AML.T0051",
		},
		{
			ID: "AML.T0051.000", Name: "LLM Prompt Injection: Direct",
			Description: "Direct prompt injection against the LLM interface.",
			TacticID:    TacticExecution, TacticName: "Execution",
			URL: "https://atlas.mitre.org/techniques/AML.T0051",
		},
		{
			ID: "AML.T0051.001", Name: "LLM Prompt Injection: Indirect",
			Description: "Injection via document/content processed by the LLM.",
			TacticID:    TacticExecution, TacticName: "Execution",
			URL: "https://atlas.mitre.org/techniques/AML.T0051",
		},
		{
			ID: "AML.T0057", Name: "LLM Data Leakage",
			Description: "The LLM reveals sensitive data from training, system prompt, or context.",
			TacticID:    TacticCollection, TacticName: "Collection",
			URL: "https://atlas.mitre.org/techniques/AML.T0057",
		},
		{
			ID: "AML.T0024", Name: "Exfiltration via ML Inference API",
			Description: "Adversary extracts information via repeated or specially-crafted inference API calls.",
			TacticID:    TacticExfiltration, TacticName: "Exfiltration",
			URL: "https://atlas.mitre.org/techniques/AML.T0024",
		},
		{
			ID: "AML.T0029", Name: "Denial of ML Service",
			Description: "Adversary induces expensive or recursive ML operations to exhaust resources.",
			TacticID:    TacticExecution, TacticName: "Execution",
			URL: "https://atlas.mitre.org/techniques/AML.T0029",
		},
		{
			ID: "AML.T0043", Name: "Craft Adversarial Data",
			Description: "Adversary crafts inputs that cause misclassification.",
			TacticID:    TacticExecution, TacticName: "Execution",
			URL: "https://atlas.mitre.org/techniques/AML.T0043",
		},
		{
			ID: "AML.T0050", Name: "Command and Scripting Interpreter (LLM)",
			Description: "Adversary uses LLM outputs to drive downstream command execution.",
			TacticID:    TacticExecution, TacticName: "Execution",
			URL: "https://atlas.mitre.org/techniques/AML.T0050",
		},
	}
}

// Lookup returns the technique with the given ID, or nil.
func Lookup(techniques []Technique, id string) *Technique {
	for i := range techniques {
		if techniques[i].ID == id {
			return &techniques[i]
		}
	}
	return nil
}
