package llm

import (
	"fmt"
	"regexp"
	"strings"

	"samcrider/csp/core"
)

// DLPScanner implements Data Loss Prevention scanning
type DLPScanner struct {
	patterns []*regexp.Regexp
	policy   *core.Policy
}

// NewDLPScanner creates a new DLP scanner with the specified patterns
func NewDLPScanner(patterns []string, policy *core.Policy) (*DLPScanner, error) {
	compiledPatterns := make([]*regexp.Regexp, 0, len(patterns))

	// Compile all patterns
	for _, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid DLP pattern: %w", err)
		}
		compiledPatterns = append(compiledPatterns, compiled)
	}

	return &DLPScanner{
		patterns: compiledPatterns,
		policy:   policy,
	}, nil
}

// ScanContent checks for restricted patterns in content
func (d *DLPScanner) ScanContent(content string) ([]string, error) {
	violations := []string{}

	// Check custom DLP patterns
	for i, pattern := range d.patterns {
		if pattern.MatchString(content) {
			violations = append(violations, fmt.Sprintf("custom_pattern_%d", i))
		}
	}

	// Also use core scanning if policy available
	if d.policy != nil {
		matches := core.ScanText(content, d.policy)
		for _, match := range matches {
			violations = append(violations, match.Type)
		}
	}

	return violations, nil
}

// RequestValidator implements input/output validation for SOC 2 compliance
type RequestValidator struct {
	config ValidationConfig
}

// NewRequestValidator creates a new request validator
func NewRequestValidator(config ValidationConfig) *RequestValidator {
	return &RequestValidator{
		config: config,
	}
}

// ValidateInput validates request input
func (v *RequestValidator) ValidateInput(input string) error {
	if !v.config.Enabled {
		return nil
	}

	// Check length limits
	if v.config.MaxLength > 0 && len(input) > v.config.MaxLength {
		return fmt.Errorf("input exceeds maximum length of %d characters", v.config.MaxLength)
	}

	// Check for disallowed code blocks
	if v.config.DisallowCodeBlocks && (strings.Contains(input, "```") || strings.Contains(input, "```")) {
		return fmt.Errorf("input contains disallowed code blocks")
	}

	// Check for disallowed URLs
	if v.config.DisallowURLs && (strings.Contains(input, "http://") || strings.Contains(input, "https://")) {
		return fmt.Errorf("input contains disallowed URLs")
	}

	return nil
}

// validateGenerateRequest validates content and options for generation
func validateGenerateRequest(content []ContentPart, options GenerateOptions, maxContentSize int) error {
	if len(content) == 0 {
		return fmt.Errorf("content must not be empty")
	}

	if options.Model == "" {
		return fmt.Errorf("model must be specified")
	}

	if options.Temperature < 0 || options.Temperature > 1 {
		return fmt.Errorf("temperature must be between 0 and 1")
	}

	totalContentSize := 0
	for _, part := range content {
		switch part.Type {
		case "text":
			if part.Text == "" {
				return fmt.Errorf("text content part must not be empty")
			}
			totalContentSize += len(part.Text)
		case "image":
			if len(part.Image) == 0 {
				return fmt.Errorf("image content part must not be empty")
			}
			totalContentSize += len(part.Image)
		default:
			return fmt.Errorf("unsupported content type: %s", part.Type)
		}
	}

	if maxContentSize > 0 && totalContentSize > maxContentSize {
		return fmt.Errorf("total content size (%d bytes) exceeds maximum allowed (%d bytes)",
			totalContentSize, maxContentSize)
	}

	return nil
}
