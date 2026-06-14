package attack

// Techniques is an embedded lookup of the MITRE ATT&CK techniques most
// commonly referenced by IOC feeds. This is intentionally a subset of the
// full v14 enterprise matrix — adding more is additive and safe. For the
// full canonical dataset, a future milestone will embed the upstream
// `mitre-attack-stix-data` bundle.
var Techniques = map[string]Technique{
	// Initial Access
	"T1566":     {ID: "T1566", Name: "Phishing", Tactic: "initial-access"},
	"T1566.002": {ID: "T1566.002", Name: "Spearphishing Link", Tactic: "initial-access"},
	"T1566.001": {ID: "T1566.001", Name: "Spearphishing Attachment", Tactic: "initial-access"},
	"T1190":     {ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "initial-access"},

	// Execution
	"T1204":     {ID: "T1204", Name: "User Execution", Tactic: "execution"},
	"T1204.001": {ID: "T1204.001", Name: "Malicious Link", Tactic: "execution"},
	"T1204.002": {ID: "T1204.002", Name: "Malicious File", Tactic: "execution"},
	"T1059":     {ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "execution"},

	// Command and Control
	"T1071":     {ID: "T1071", Name: "Application Layer Protocol", Tactic: "command-and-control"},
	"T1071.001": {ID: "T1071.001", Name: "Web Protocols", Tactic: "command-and-control"},
	"T1071.004": {ID: "T1071.004", Name: "DNS", Tactic: "command-and-control"},
	"T1105":     {ID: "T1105", Name: "Ingress Tool Transfer", Tactic: "command-and-control"},
	"T1572":     {ID: "T1572", Name: "Protocol Tunneling", Tactic: "command-and-control"},

	// Exfiltration
	"T1041": {ID: "T1041", Name: "Exfiltration Over C2 Channel", Tactic: "exfiltration"},

	// Defense Evasion
	"T1027": {ID: "T1027", Name: "Obfuscated Files or Information", Tactic: "defense-evasion"},

	// Credential Access
	"T1110": {ID: "T1110", Name: "Brute Force", Tactic: "credential-access"},
	"T1555": {ID: "T1555", Name: "Credentials from Password Stores", Tactic: "credential-access"},

	// Impact
	"T1486": {ID: "T1486", Name: "Data Encrypted for Impact", Tactic: "impact"},
	"T1490": {ID: "T1490", Name: "Inhibit System Recovery", Tactic: "impact"},
}

// Lookup returns a technique by ID. ok=false for unknown IDs.
func Lookup(id string) (Technique, bool) {
	t, ok := Techniques[id]
	return t, ok
}
