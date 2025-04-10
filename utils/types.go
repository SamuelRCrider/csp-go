package utils

// MatchResult represents a detected sensitive data match with SOC 2 compliance metadata
type MatchResult struct {
	// Match location information
	StartIndex int
	EndIndex   int
	Value      string

	// Classification information
	Type   string
	Action string

	// SOC 2 compliance fields
	ComplianceType string // Type of compliance concern (PII, Financial, etc.)
	RiskLevel      int    // Risk level (1-4) where 4 is highest
	Description    string // Human-readable description of the match

	// Tracking information
	RequestID   string // Related request ID
	Fingerprint string // Hash fingerprint of the value for correlation
}
