package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/SamuelRCrider/csp-go/utils"
)

// ComplianceCategory defines categories for compliance classification
type ComplianceCategory string

const (
	// CompliancePII represents Personally Identifiable Information (general)
	CompliancePII ComplianceCategory = "pii"

	// ComplianceFinancial represents financial information
	ComplianceFinancial ComplianceCategory = "financial"

	// ComplianceHealth represents health information (HIPAA)
	ComplianceHealth ComplianceCategory = "health"

	// ComplianceGDPR represents GDPR-specific information
	ComplianceGDPR ComplianceCategory = "gdpr"

	// ComplianceCredential represents credentials or secrets
	ComplianceCredential ComplianceCategory = "credential"

	// ComplianceSource represents source code or intellectual property
	ComplianceSource ComplianceCategory = "source_code"
)

// RiskLevel defines the risk level of finding sensitive data
type RiskLevel int

const (
	// RiskLow represents low risk findings
	RiskLow RiskLevel = 1

	// RiskMedium represents medium risk findings
	RiskMedium RiskLevel = 2

	// RiskHigh represents high risk findings
	RiskHigh RiskLevel = 3

	// RiskCritical represents critical risk findings
	RiskCritical RiskLevel = 4
)

// ScannerConfig defines configuration for DLP scanning
type ScannerConfig struct {
	// EnabledCategories specifies which compliance categories to scan for
	EnabledCategories []ComplianceCategory

	// CustomPatterns allows adding custom regex patterns
	CustomPatterns map[string]string

	// MinimumRiskLevel is the minimum risk level to report
	MinimumRiskLevel RiskLevel

	// EnableFingerprinting enables data fingerprinting for high-value data
	EnableFingerprinting bool

	// MaxScanSizeBytes limits the maximum text size to scan
	MaxScanSizeBytes int
}

// PatternInfo stores metadata about a pattern
type PatternInfo struct {
	Regex            *regexp.Regexp
	ComplianceType   ComplianceCategory
	RiskLevel        RiskLevel
	Description      string
	ExampleRedaction string
}

// Enhanced PII patterns for SOC 2 compliant DLP scanning
var enhancedPIIPatterns = map[string]PatternInfo{
	// Personal Identifiers
	"email": {
		Regex:            regexp.MustCompile(`[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`),
		ComplianceType:   CompliancePII,
		RiskLevel:        RiskMedium,
		Description:      "Email address",
		ExampleRedaction: "[EMAIL]",
	},
	"ssn_us": {
		Regex:            regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		ComplianceType:   CompliancePII,
		RiskLevel:        RiskHigh,
		Description:      "US Social Security Number",
		ExampleRedaction: "[US-SSN]",
	},
	"phone_us": {
		Regex:            regexp.MustCompile(`\(?\d{3}\)?[-.\\s]?\d{3}[-.\\s]?\d{4}`),
		ComplianceType:   CompliancePII,
		RiskLevel:        RiskMedium,
		Description:      "US Phone Number",
		ExampleRedaction: "[PHONE]",
	},
	"zip_us": {
		Regex:            regexp.MustCompile(`\b\d{5}(?:-\d{4})?\b`),
		ComplianceType:   CompliancePII,
		RiskLevel:        RiskLow,
		Description:      "US ZIP Code",
		ExampleRedaction: "[ZIP]",
	},
	"ip_address": {
		Regex:            regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
		ComplianceType:   CompliancePII,
		RiskLevel:        RiskLow,
		Description:      "IP Address",
		ExampleRedaction: "[IP-ADDR]",
	},

	// Financial Information
	"credit_card": {
		Regex:            regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`),
		ComplianceType:   ComplianceFinancial,
		RiskLevel:        RiskHigh,
		Description:      "Credit Card Number",
		ExampleRedaction: "[CREDIT-CARD]",
	},
	"bank_account_us": {
		Regex:            regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`),
		ComplianceType:   ComplianceFinancial,
		RiskLevel:        RiskHigh,
		Description:      "Bank Account Number",
		ExampleRedaction: "[BANK-ACCT]",
	},

	// Credentials
	"api_key": {
		Regex:            regexp.MustCompile(`\b(?:api[-_]?key|access[-_]?key|token)[-_]?[=:]\s*["']?[a-zA-Z0-9_\-.=+/]{16,}["']?`),
		ComplianceType:   ComplianceCredential,
		RiskLevel:        RiskCritical,
		Description:      "API Key",
		ExampleRedaction: "[API-KEY]",
	},
	"password_pattern": {
		Regex:            regexp.MustCompile(`\b(?:password|passwd|pwd)[-_]?[=:]\s*["']?[^\s"']{6,}["']?`),
		ComplianceType:   ComplianceCredential,
		RiskLevel:        RiskCritical,
		Description:      "Password in text",
		ExampleRedaction: "[PASSWORD]",
	},

	// Health Information
	"medical_record": {
		Regex:            regexp.MustCompile(`\b(?:mrn|medical record number|patient id)[=:]\s*\d{6,}\b`),
		ComplianceType:   ComplianceHealth,
		RiskLevel:        RiskHigh,
		Description:      "Medical Record Number",
		ExampleRedaction: "[MEDICAL-RECORD]",
	},

	// GDPR-specific
	"national_id_eu": {
		Regex:            regexp.MustCompile(`\b[A-Z]{2}[-_][A-Z0-9]{6,12}\b`),
		ComplianceType:   ComplianceGDPR,
		RiskLevel:        RiskHigh,
		Description:      "EU National ID",
		ExampleRedaction: "[EU-ID]",
	},
}

// DLPScanner provides SOC 2 compliant data loss prevention scanning
type DLPScanner struct {
	config       ScannerConfig
	patterns     map[string]PatternInfo
	policy       *Policy
	fingerprints map[string]string
	mu           sync.Mutex
}

// NewDLPScanner creates a new DLP scanner with the specified configuration
func NewDLPScanner(config ScannerConfig, policy *Policy) (*DLPScanner, error) {
	// Copy built-in patterns
	patterns := make(map[string]PatternInfo)
	for k, v := range enhancedPIIPatterns {
		patterns[k] = v
	}

	// Add custom patterns
	for name, pattern := range config.CustomPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid custom pattern '%s': %w", name, err)
		}

		patterns[name] = PatternInfo{
			Regex:          re,
			ComplianceType: CompliancePII, // Default to PII
			RiskLevel:      RiskMedium,    // Default to medium risk
			Description:    fmt.Sprintf("Custom pattern: %s", name),
		}
	}

	return &DLPScanner{
		config:       config,
		patterns:     patterns,
		policy:       policy,
		fingerprints: make(map[string]string),
	}, nil
}

// createFingerprint creates a fingerprint hash of the data
func (s *DLPScanner) createFingerprint(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// AddFingerprint adds a sensitive data fingerprint to detect in future scans
func (s *DLPScanner) AddFingerprint(name, data string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fingerprint := s.createFingerprint(data)
	s.fingerprints[fingerprint] = name
}

// ScanText scans text with enhanced DLP capabilities
func (s *DLPScanner) ScanText(text string) (*ScanResult, error) {
	// Check max size
	if s.config.MaxScanSizeBytes > 0 && len(text) > s.config.MaxScanSizeBytes {
		return nil, fmt.Errorf("text exceeds maximum scan size of %d bytes", s.config.MaxScanSizeBytes)
	}

	result := &ScanResult{
		Matches:          []utils.MatchResult{},
		DetectedPatterns: make(map[string]int),
		RiskAssessment: RiskAssessment{
			HighestRisk: RiskLow,
		},
	}

	// Scan using patterns
	for patternName, info := range s.patterns {
		// Skip if category not enabled (empty list means all enabled)
		if len(s.config.EnabledCategories) > 0 {
			categoryEnabled := false
			for _, category := range s.config.EnabledCategories {
				if category == info.ComplianceType {
					categoryEnabled = true
					break
				}
			}
			if !categoryEnabled {
				continue
			}
		}

		// Skip if below minimum risk level
		if info.RiskLevel < s.config.MinimumRiskLevel {
			continue
		}

		// Scan for pattern
		locs := info.Regex.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			match := utils.MatchResult{
				StartIndex:     loc[0],
				EndIndex:       loc[1],
				Value:          text[loc[0]:loc[1]],
				Type:           patternName,
				Action:         "redact",
				ComplianceType: string(info.ComplianceType),
				RiskLevel:      int(info.RiskLevel),
				Description:    info.Description,
			}

			result.Matches = append(result.Matches, match)
			result.DetectedPatterns[patternName]++

			// Update highest risk level
			if info.RiskLevel > result.RiskAssessment.HighestRisk {
				result.RiskAssessment.HighestRisk = info.RiskLevel
				result.RiskAssessment.HighestRiskCategory = info.ComplianceType
			}
		}
	}

	// Check for fingerprinted data if enabled
	if s.config.EnableFingerprinting {
		// Check for word-level matches (more efficient than checking every substring)
		words := strings.Fields(text)
		for _, word := range words {
			if len(word) >= 8 { // Only check words of reasonable length
				fingerprint := s.createFingerprint(word)
				if name, exists := s.fingerprints[fingerprint]; exists {
					match := utils.MatchResult{
						StartIndex:     strings.Index(text, word),
						EndIndex:       strings.Index(text, word) + len(word),
						Value:          word,
						Type:           "fingerprinted_data",
						Action:         "redact",
						ComplianceType: "fingerprinted",
						RiskLevel:      int(RiskHigh),
						Description:    fmt.Sprintf("Fingerprinted sensitive data: %s", name),
					}

					result.Matches = append(result.Matches, match)
					result.DetectedPatterns["fingerprinted_data"]++
					result.RiskAssessment.HighestRisk = RiskHigh
					result.RiskAssessment.HighestRiskCategory = "fingerprinted"
				}
			}
		}
	}

	// Apply policy rules
	if s.policy != nil {
		policyMatches := ScanWithPolicy(text, s.policy, nil)
		result.Matches = append(result.Matches, policyMatches...)

		for _, match := range policyMatches {
			result.DetectedPatterns[match.Type]++
		}
	}

	// Calculate statistics
	result.TotalMatches = len(result.Matches)
	result.ContainsSensitiveData = result.TotalMatches > 0

	// Set compliance status based on risk level
	result.CompliantStatus = result.RiskAssessment.HighestRisk <= RiskLow

	return result, nil
}

// ScanResult contains the results of a DLP scan with compliance information
type ScanResult struct {
	// List of matches
	Matches []utils.MatchResult

	// Total match count
	TotalMatches int

	// Count of each detected pattern
	DetectedPatterns map[string]int

	// Whether sensitive data was found
	ContainsSensitiveData bool

	// Compliance assessment
	CompliantStatus bool

	// Risk assessment
	RiskAssessment RiskAssessment
}

// RiskAssessment provides a risk evaluation of detected sensitive data
type RiskAssessment struct {
	// Highest risk level found
	HighestRisk RiskLevel

	// Category with highest risk
	HighestRiskCategory ComplianceCategory
}

// ScanWithPolicy scans text using policy rules
func ScanWithPolicy(text string, policy *Policy, ctx *Context) []utils.MatchResult {
	var results []utils.MatchResult

	// Apply policy rules with context check if provided
	for _, rule := range policy.Rules {
		if ctx != nil && !IsRuleApplicable(rule, ctx) {
			continue
		}

		switch rule.Type {
		case "regex":
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				continue
			}
			locs := re.FindAllStringIndex(text, -1)
			for _, loc := range locs {
				results = append(results, utils.MatchResult{
					StartIndex: loc[0],
					EndIndex:   loc[1],
					Value:      text[loc[0]:loc[1]],
					Type:       rule.Match,
					Action:     string(rule.Action),
				})
			}
		case "string":
			for _, val := range rule.Values {
				idx := strings.Index(text, val)
				for idx != -1 {
					results = append(results, utils.MatchResult{
						StartIndex: idx,
						EndIndex:   idx + len(val),
						Value:      val,
						Type:       rule.Match,
						Action:     string(rule.Action),
					})
					startPos := idx + 1
					if startPos >= len(text) {
						break
					}
					nextIdx := strings.Index(text[startPos:], val)
					if nextIdx == -1 {
						break
					}
					idx = startPos + nextIdx
				}
			}
		}
	}

	return results
}

// ScanText scans the input text using both regex-based policy rules and built-in DLP rules (legacy function)
func ScanText(text string, policy *Policy) []utils.MatchResult {
	// Create a default scanner with basic settings
	scanner, err := NewDLPScanner(ScannerConfig{
		EnableFingerprinting: false,
		MinimumRiskLevel:     RiskLow,
	}, policy)

	if err != nil {
		// Fallback to direct policy scanning
		return ScanWithPolicy(text, policy, nil)
	}

	result, err := scanner.ScanText(text)
	if err != nil {
		// Fallback to direct policy scanning
		return ScanWithPolicy(text, policy, nil)
	}

	return result.Matches
}

// ScanTextWithContext applies rules only if they match the provided context (legacy function)
func ScanTextWithContext(text string, policy *Policy, ctx *Context) []utils.MatchResult {
	// Create a default scanner with basic settings
	scanner, err := NewDLPScanner(ScannerConfig{
		EnableFingerprinting: false,
		MinimumRiskLevel:     RiskLow,
	}, policy)

	if err != nil {
		// Fallback to direct policy scanning with context
		return ScanWithPolicy(text, policy, ctx)
	}

	result, err := scanner.ScanText(text)
	if err != nil {
		// Fallback to direct policy scanning with context
		return ScanWithPolicy(text, policy, ctx)
	}

	// Filter results by context
	if ctx != nil {
		var contextFiltered []utils.MatchResult
		for _, match := range result.Matches {
			// Include built-in matches and policy matches that apply to this context
			if match.ComplianceType != "" || IsContextMatch(match.Type, ctx, policy) {
				contextFiltered = append(contextFiltered, match)
			}
		}
		return contextFiltered
	}

	return result.Matches
}

// IsContextMatch checks if a match type applies to the given context based on policy
func IsContextMatch(matchType string, ctx *Context, policy *Policy) bool {
	for _, rule := range policy.Rules {
		if rule.Match == matchType {
			return IsRuleApplicable(rule, ctx)
		}
	}
	return true // If no specific rule, assume it applies
}

// PostScanAndRedact scans a model's output for sensitive content and applies redactions (legacy function)
func PostScanAndRedact(response string, policy *Policy, ctx *Context) string {
	// Use new scanner but maintain legacy behavior
	matches := ScanTextWithContext(response, policy, ctx)
	return ApplyRedactions(response, matches)
}
