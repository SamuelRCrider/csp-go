package core

import (
	"sort"
	"strings"

	"github.com/SamuelRCrider/csp-go/utils"
)

func ApplyRedactions(text string, matches []utils.MatchResult) string {
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].StartIndex < matches[j].StartIndex
	})

	var builder strings.Builder
	lastIndex := 0

	for _, match := range matches {
		if match.StartIndex > lastIndex {
			builder.WriteString(text[lastIndex:match.StartIndex])
		}

		switch match.Action {
		case "redact":
			builder.WriteString("[REDACTED:" + match.Type + "]")
		case "mask":
			builder.WriteString("[MASKED:" + match.Type + "]")
		case "encrypt":
			builder.WriteString("[ENCRYPTED:" + match.Type + "]")
		default:
			builder.WriteString(text[match.StartIndex:match.EndIndex])
		}

		lastIndex = match.EndIndex
	}

	if lastIndex < len(text) {
		builder.WriteString(text[lastIndex:])
	}

	return builder.String()
}
