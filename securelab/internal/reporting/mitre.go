// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

// Package reporting generates coverage reports, HTML dashboards, SARIF output,
// and MITRE ATT&CK mappings for SecureLab scenario runs.
package reporting

import "strings"

// MITREEntry maps a SecureLab attack kind to a MITRE ATT&CK technique.
type MITREEntry struct {
	AttackKind  string
	TechniqueID string
	Name        string
	Tactic      string
	URL         string
}

// MITREMapping maps all 15 SecureLab attack kinds to MITRE ATT&CK technique IDs.
// Reference: https://attack.mitre.org/techniques/
var MITREMapping = map[string]MITREEntry{
	"bola": {
		AttackKind:  "bola",
		TechniqueID: "T1078",
		Name:        "Valid Accounts",
		Tactic:      "Initial Access, Defense Evasion, Persistence, Privilege Escalation",
		URL:         "https://attack.mitre.org/techniques/T1078/",
	},
	"authbypass": {
		AttackKind:  "authbypass",
		TechniqueID: "T1550.001",
		Name:        "Use Alternate Authentication Material: Application Access Token",
		Tactic:      "Defense Evasion, Lateral Movement",
		URL:         "https://attack.mitre.org/techniques/T1550/001/",
	},
	"massassignment": {
		AttackKind:  "massassignment",
		TechniqueID: "T1548",
		Name:        "Abuse Elevation Control Mechanism",
		Tactic:      "Defense Evasion, Privilege Escalation",
		URL:         "https://attack.mitre.org/techniques/T1548/",
	},
	"ratelimitbypass": {
		AttackKind:  "ratelimitbypass",
		TechniqueID: "T1499",
		Name:        "Endpoint Denial of Service",
		Tactic:      "Impact",
		URL:         "https://attack.mitre.org/techniques/T1499/",
	},
	"ssrf": {
		AttackKind:  "ssrf",
		TechniqueID: "T1090",
		Name:        "Proxy",
		Tactic:      "Command and Control",
		URL:         "https://attack.mitre.org/techniques/T1090/",
	},
	"misconfiguration": {
		AttackKind:  "misconfiguration",
		TechniqueID: "T1592",
		Name:        "Gather Victim Host Information",
		Tactic:      "Reconnaissance",
		URL:         "https://attack.mitre.org/techniques/T1592/",
	},
	"synflood": {
		AttackKind:  "synflood",
		TechniqueID: "T1498.001",
		Name:        "Network Denial of Service: Direct Network Flood",
		Tactic:      "Impact",
		URL:         "https://attack.mitre.org/techniques/T1498/001/",
	},
	"udpflood": {
		AttackKind:  "udpflood",
		TechniqueID: "T1498.001",
		Name:        "Network Denial of Service: Direct Network Flood",
		Tactic:      "Impact",
		URL:         "https://attack.mitre.org/techniques/T1498/001/",
	},
	"httpflood": {
		AttackKind:  "httpflood",
		TechniqueID: "T1499.003",
		Name:        "Endpoint Denial of Service: Application Exhaustion Flood",
		Tactic:      "Impact",
		URL:         "https://attack.mitre.org/techniques/T1499/003/",
	},
	"slowloris": {
		AttackKind:  "slowloris",
		TechniqueID: "T1499.001",
		Name:        "Endpoint Denial of Service: OS Exhaustion Flood",
		Tactic:      "Impact",
		URL:         "https://attack.mitre.org/techniques/T1499/001/",
	},
	"portscan": {
		AttackKind:  "portscan",
		TechniqueID: "T1046",
		Name:        "Network Service Discovery",
		Tactic:      "Discovery",
		URL:         "https://attack.mitre.org/techniques/T1046/",
	},
	"endpointenum": {
		AttackKind:  "endpointenum",
		TechniqueID: "T1595.003",
		Name:        "Active Scanning: Wordlist Scanning",
		Tactic:      "Reconnaissance",
		URL:         "https://attack.mitre.org/techniques/T1595/003/",
	},
	"versiondetect": {
		AttackKind:  "versiondetect",
		TechniqueID: "T1082",
		Name:        "System Information Discovery",
		Tactic:      "Discovery",
		URL:         "https://attack.mitre.org/techniques/T1082/",
	},
	"dataexfil": {
		AttackKind:  "dataexfil",
		TechniqueID: "T1530",
		Name:        "Data from Cloud Storage",
		Tactic:      "Collection",
		URL:         "https://attack.mitre.org/techniques/T1530/",
	},
	"dnstunnel": {
		AttackKind:  "dnstunnel",
		TechniqueID: "T1071.004",
		Name:        "Application Layer Protocol: DNS",
		Tactic:      "Command and Control",
		URL:         "https://attack.mitre.org/techniques/T1071/004/",
	},
}

// LookupByKind returns the MITREEntry for an attack kind (case-insensitive).
// Returns the zero value and false if not found.
func LookupByKind(kind string) (MITREEntry, bool) {
	entry, ok := MITREMapping[strings.ToLower(kind)]
	return entry, ok
}
