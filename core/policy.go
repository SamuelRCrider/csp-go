package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Action defines what happens when a rule matches
type Action string

const (
	// ActionRedact replaces sensitive data with a placeholder
	ActionRedact Action = "redact"

	// ActionMask partially redacts sensitive data
	ActionMask Action = "mask"

	// ActionEncrypt encrypts sensitive data
	ActionEncrypt Action = "encrypt"

	// ActionTokenize replaces sensitive data with a token
	ActionTokenize Action = "tokenize"

	// ActionAlert logs an alert but doesn't modify the content
	ActionAlert Action = "alert"

	// ActionBlock blocks the operation entirely
	ActionBlock Action = "block"
)

// ComplianceFramework identifies specific compliance frameworks
type ComplianceFramework string

const (
	// FrameworkSOC2 represents SOC 2 compliance
	FrameworkSOC2 ComplianceFramework = "soc2"

	// FrameworkGDPR represents GDPR compliance
	FrameworkGDPR ComplianceFramework = "gdpr"

	// FrameworkHIPAA represents HIPAA compliance
	FrameworkHIPAA ComplianceFramework = "hipaa"

	// FrameworkPCI represents PCI-DSS compliance
	FrameworkPCI ComplianceFramework = "pci"
)

// PolicyMetadata contains information about the policy
type PolicyMetadata struct {
	// Version of the policy
	Version string `yaml:"version"`

	// When the policy was created
	CreatedAt time.Time `yaml:"created_at"`

	// Last modification time
	UpdatedAt time.Time `yaml:"updated_at"`

	// Description of the policy
	Description string `yaml:"description"`

	// Author of the policy
	Author string `yaml:"author"`

	// Hash of the policy content for integrity verification
	Hash string `yaml:"hash,omitempty"`

	// Compliance frameworks this policy addresses
	Frameworks []ComplianceFramework `yaml:"frameworks,omitempty"`
}

// Rule represents a security policy rule with optional conditions
type Rule struct {
	// Unique identifier for the rule
	ID string `yaml:"id"`

	// Name of the pattern this rule matches
	Match string `yaml:"match"`

	// Type of rule: "regex", "string", etc.
	Type string `yaml:"type"`

	// Regex pattern to match
	Pattern string `yaml:"pattern,omitempty"`

	// List of strings to match
	Values []string `yaml:"values,omitempty"`

	// What action to take when this rule matches
	Action Action `yaml:"action"`

	// Risk level (1-4) where 4 is highest
	RiskLevel int `yaml:"risk_level,omitempty"`

	// Conditions under which this rule applies
	Conditions struct {
		// Roles for which this rule applies
		Roles []string `yaml:"roles,omitempty"`

		// Organizations for which this rule applies
		Organizations []string `yaml:"organizations,omitempty"`

		// Environments for which this rule applies (e.g., "production", "staging")
		Environments []string `yaml:"environments,omitempty"`
	} `yaml:"conditions,omitempty"`

	// Compliance frameworks this rule addresses
	Frameworks []ComplianceFramework `yaml:"frameworks,omitempty"`

	// Description of the rule
	Description string `yaml:"description,omitempty"`
}

// Policy defines a complete security policy
type Policy struct {
	// Metadata about the policy
	Metadata PolicyMetadata `yaml:"metadata"`

	// Rules contained in the policy
	Rules []Rule `yaml:"rules"`

	// Default action if no rules match
	DefaultAction Action `yaml:"default_action,omitempty"`
}

// Context contains information about the current request context
type Context struct {
	// User role
	Role string

	// User ID for tracking
	UserID string

	// Organization ID
	OrganizationID string

	// Environment (production, staging, etc.)
	Environment string

	// Request ID for tracking
	RequestID string

	// IP address of the client
	IPAddress string
}

// PolicyVersion tracks a specific version of a policy
type PolicyVersion struct {
	// Version identifier
	Version string

	// Path to the policy file
	Path string

	// Timestamp when this version was created
	Timestamp time.Time
}

// PolicyManager manages policy loading, versioning, and auditing
type PolicyManager struct {
	// Currently active policy
	ActivePolicy *Policy

	// Base directory for policy files
	PolicyDir string

	// History of policy versions
	VersionHistory []PolicyVersion

	// Whether to automatically archive changed policies
	EnableVersioning bool
}

// NewPolicyManager creates a new policy manager
func NewPolicyManager(policyDir string, enableVersioning bool) *PolicyManager {
	return &PolicyManager{
		PolicyDir:        policyDir,
		EnableVersioning: enableVersioning,
		VersionHistory:   []PolicyVersion{},
	}
}

// LoadPolicy reads a YAML policy file and unmarshals it into a Policy struct
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	// Validate policy
	if err := validatePolicy(&policy); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	// Generate hash for integrity checking
	hash := calculatePolicyHash(data)
	policy.Metadata.Hash = hash

	// Ensure all rules have IDs
	for i := range policy.Rules {
		if policy.Rules[i].ID == "" {
			policy.Rules[i].ID = fmt.Sprintf("rule-%d", i+1)
		}
	}

	return &policy, nil
}

// LoadAndTrackPolicy loads a policy and tracks it in the version history
func (pm *PolicyManager) LoadAndTrackPolicy(path string) error {
	policy, err := LoadPolicy(path)
	if err != nil {
		return err
	}

	// Set active policy
	pm.ActivePolicy = policy

	// Track in version history
	if pm.EnableVersioning {
		version := PolicyVersion{
			Version:   policy.Metadata.Version,
			Path:      path,
			Timestamp: time.Now(),
		}
		pm.VersionHistory = append(pm.VersionHistory, version)

		// Archive a copy if this is a new version
		if len(pm.VersionHistory) > 1 {
			previousVersion := pm.VersionHistory[len(pm.VersionHistory)-2]
			if previousVersion.Version != version.Version {
				pm.archivePolicy(path, policy.Metadata.Version)
			}
		}
	}

	// Log policy load
	LogSecurityEvent("system", "policy_loaded", SeverityInfo, "system", map[string]string{
		"policy_version": policy.Metadata.Version,
		"policy_path":    path,
		"rule_count":     fmt.Sprintf("%d", len(policy.Rules)),
	})

	return nil
}

// archivePolicy saves a copy of the policy file to the archive directory
func (pm *PolicyManager) archivePolicy(path string, version string) error {
	// Create archive directory if it doesn't exist
	archiveDir := filepath.Join(pm.PolicyDir, "archive")
	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		return fmt.Errorf("failed to create archive directory: %w", err)
	}

	// Read original file
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	// Create archive filename
	timestamp := time.Now().Format("20060102-150405")
	archivePath := filepath.Join(archiveDir, fmt.Sprintf("policy-%s-%s.yaml", version, timestamp))

	// Write to archive
	if err := ioutil.WriteFile(archivePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write policy archive: %w", err)
	}

	return nil
}

// SavePolicy saves a policy to disk and updates the version history
func (pm *PolicyManager) SavePolicy(policy *Policy, path string) error {
	// Update metadata
	policy.Metadata.UpdatedAt = time.Now()

	// Serialize to YAML
	data, err := yaml.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to serialize policy: %w", err)
	}

	// Update hash
	policy.Metadata.Hash = calculatePolicyHash(data)

	// Re-serialize with updated hash
	data, err = yaml.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to re-serialize policy with hash: %w", err)
	}

	// Write to file
	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	// Update active policy
	pm.ActivePolicy = policy

	// Track in version history
	if pm.EnableVersioning {
		version := PolicyVersion{
			Version:   policy.Metadata.Version,
			Path:      path,
			Timestamp: time.Now(),
		}
		pm.VersionHistory = append(pm.VersionHistory, version)
	}

	// Log policy update
	LogSecurityEvent("system", "policy_updated", SeverityInfo, "system", map[string]string{
		"policy_version": policy.Metadata.Version,
		"policy_path":    path,
		"rule_count":     fmt.Sprintf("%d", len(policy.Rules)),
	})

	return nil
}

// ValidatePolicy checks if a policy is valid
func validatePolicy(policy *Policy) error {
	// Check if any rules are invalid
	for i, rule := range policy.Rules {
		if rule.Match == "" {
			return fmt.Errorf("rule %d has no match pattern", i)
		}

		if rule.Type == "" {
			return fmt.Errorf("rule %d has no type", i)
		}

		if rule.Type == "regex" && rule.Pattern == "" {
			return fmt.Errorf("regex rule %d has no pattern", i)
		}

		if rule.Type == "string" && len(rule.Values) == 0 {
			return fmt.Errorf("string rule %d has no values", i)
		}
	}

	return nil
}

// calculatePolicyHash generates a hash of the policy content for integrity checking
func calculatePolicyHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// IsRuleApplicable checks if a rule applies given a context
func IsRuleApplicable(rule Rule, ctx *Context) bool {
	// If no conditions are specified, the rule applies
	if len(rule.Conditions.Roles) == 0 &&
		len(rule.Conditions.Organizations) == 0 &&
		len(rule.Conditions.Environments) == 0 {
		return true
	}

	// Check role conditions
	if len(rule.Conditions.Roles) > 0 {
		roleMatch := false
		for _, r := range rule.Conditions.Roles {
			if r == ctx.Role {
				roleMatch = true
				break
			}
		}
		if !roleMatch {
			return false
		}
	}

	// Check organization conditions
	if len(rule.Conditions.Organizations) > 0 && ctx.OrganizationID != "" {
		orgMatch := false
		for _, org := range rule.Conditions.Organizations {
			if org == ctx.OrganizationID {
				orgMatch = true
				break
			}
		}
		if !orgMatch {
			return false
		}
	}

	// Check environment conditions
	if len(rule.Conditions.Environments) > 0 && ctx.Environment != "" {
		envMatch := false
		for _, env := range rule.Conditions.Environments {
			if env == ctx.Environment {
				envMatch = true
				break
			}
		}
		if !envMatch {
			return false
		}
	}

	return true
}

// GenerateDefaultPolicy creates a basic policy with SOC 2 compliant rules
func GenerateDefaultPolicy() *Policy {
	return &Policy{
		Metadata: PolicyMetadata{
			Version:     "1.0.0",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Description: "Default SOC 2 compliant security policy",
			Author:      "CSP-Go",
			Frameworks:  []ComplianceFramework{FrameworkSOC2},
		},
		Rules: []Rule{
			{
				ID:          "pii-email",
				Match:       "email",
				Type:        "regex",
				Pattern:     `[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`,
				Action:      ActionRedact,
				RiskLevel:   2,
				Description: "Detect and redact email addresses",
				Frameworks:  []ComplianceFramework{FrameworkSOC2, FrameworkGDPR},
			},
			{
				ID:          "pii-ssn",
				Match:       "ssn",
				Type:        "regex",
				Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
				Action:      ActionEncrypt,
				RiskLevel:   3,
				Description: "Detect and encrypt US Social Security Numbers",
				Frameworks:  []ComplianceFramework{FrameworkSOC2, FrameworkHIPAA},
			},
			{
				ID:          "financial-credit-card",
				Match:       "credit_card",
				Type:        "regex",
				Pattern:     `\b(?:\d[ -]*?){13,16}\b`,
				Action:      ActionMask,
				RiskLevel:   3,
				Description: "Detect and mask credit card numbers",
				Frameworks:  []ComplianceFramework{FrameworkSOC2, FrameworkPCI},
			},
		},
		DefaultAction: ActionAlert,
	}
}
