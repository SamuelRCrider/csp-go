package core

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// PolicyBuilder provides a fluent interface for creating security policies
type PolicyBuilder struct {
	policy *Policy
}

// NewPolicyBuilder creates a new policy builder
func NewPolicyBuilder() *PolicyBuilder {
	return &PolicyBuilder{
		policy: &Policy{
			Metadata: PolicyMetadata{
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			Rules:         []Rule{},
			DefaultAction: ActionAlert,
		},
	}
}

// WithMetadata sets the policy metadata
func (b *PolicyBuilder) WithMetadata(version, description, author string) *PolicyBuilder {
	b.policy.Metadata.Version = version
	b.policy.Metadata.Description = description
	b.policy.Metadata.Author = author
	return b
}

// WithFrameworks adds compliance frameworks to the policy
func (b *PolicyBuilder) WithFrameworks(frameworks ...ComplianceFramework) *PolicyBuilder {
	b.policy.Metadata.Frameworks = frameworks
	return b
}

// WithDefaultAction sets the default action for the policy
func (b *PolicyBuilder) WithDefaultAction(action Action) *PolicyBuilder {
	b.policy.DefaultAction = action
	return b
}

// AddRule adds a rule to the policy
func (b *PolicyBuilder) AddRule(id, match, ruleType, pattern string, action Action) *PolicyBuilder {
	rule := Rule{
		ID:      id,
		Match:   match,
		Type:    ruleType,
		Pattern: pattern,
		Action:  action,
	}
	b.policy.Rules = append(b.policy.Rules, rule)
	return b
}

// AddRuleWithRiskLevel adds a rule with a specified risk level
func (b *PolicyBuilder) AddRuleWithRiskLevel(id, match, ruleType, pattern string, action Action, riskLevel int) *PolicyBuilder {
	rule := Rule{
		ID:        id,
		Match:     match,
		Type:      ruleType,
		Pattern:   pattern,
		Action:    action,
		RiskLevel: riskLevel,
	}
	b.policy.Rules = append(b.policy.Rules, rule)
	return b
}

// AddRuleWithValues adds a rule that matches specific values instead of a pattern
func (b *PolicyBuilder) AddRuleWithValues(id, match, ruleType string, values []string, action Action) *PolicyBuilder {
	rule := Rule{
		ID:     id,
		Match:  match,
		Type:   ruleType,
		Values: values,
		Action: action,
	}
	b.policy.Rules = append(b.policy.Rules, rule)
	return b
}

// ConfigureLastRule configures additional properties for the last added rule
func (b *PolicyBuilder) ConfigureLastRule() *RuleConfigurator {
	if len(b.policy.Rules) == 0 {
		// Create an empty rule if none exists
		b.policy.Rules = append(b.policy.Rules, Rule{})
	}

	return &RuleConfigurator{
		builder: b,
		rule:    &b.policy.Rules[len(b.policy.Rules)-1],
	}
}

// Build constructs and returns the final policy
func (b *PolicyBuilder) Build() *Policy {
	// Update the updatedAt timestamp to be accurate
	b.policy.Metadata.UpdatedAt = time.Now()
	return b.policy
}

// RuleConfigurator provides methods to configure a rule
type RuleConfigurator struct {
	builder *PolicyBuilder
	rule    *Rule
}

// WithDescription sets the description for the rule
func (c *RuleConfigurator) WithDescription(description string) *RuleConfigurator {
	c.rule.Description = description
	return c
}

// WithRiskLevel sets the risk level for the rule
func (c *RuleConfigurator) WithRiskLevel(level int) *RuleConfigurator {
	c.rule.RiskLevel = level
	return c
}

// WithFrameworks adds compliance frameworks to the rule
func (c *RuleConfigurator) WithFrameworks(frameworks ...ComplianceFramework) *RuleConfigurator {
	c.rule.Frameworks = frameworks
	return c
}

// ForRoles specifies the roles this rule applies to
func (c *RuleConfigurator) ForRoles(roles ...string) *RuleConfigurator {
	c.rule.Conditions.Roles = roles
	return c
}

// ForOrganizations specifies the organizations this rule applies to
func (c *RuleConfigurator) ForOrganizations(orgs ...string) *RuleConfigurator {
	c.rule.Conditions.Organizations = orgs
	return c
}

// ForEnvironments specifies the environments this rule applies to
func (c *RuleConfigurator) ForEnvironments(envs ...string) *RuleConfigurator {
	c.rule.Conditions.Environments = envs
	return c
}

// Done returns to the policy builder
func (c *RuleConfigurator) Done() *PolicyBuilder {
	return c.builder
}

// SavePolicy saves a policy to a YAML file
func SavePolicy(policy *Policy, path string) error {
	data, err := yaml.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	// Calculate and update the hash for integrity checking
	hash := calculatePolicyHash(data)
	policy.Metadata.Hash = hash

	// Re-marshal with the updated hash
	data, err = yaml.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to re-marshal policy with hash: %w", err)
	}

	err = os.WriteFile(path, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	return nil
}
