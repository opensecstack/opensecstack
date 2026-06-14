package mentions

import (
	"regexp"
	"strings"
)

var mentionRe = regexp.MustCompile(`(?:^|\s|>)@([a-zA-Z0-9_]{2,30})`)

// Extract returns unique lowercase usernames mentioned in text.
func Extract(text string) []string {
	matches := mentionRe.FindAllStringSubmatch(text, -1)
	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		username := strings.ToLower(m[1])
		if !seen[username] {
			seen[username] = true
			result = append(result, username)
		}
	}
	return result
}
