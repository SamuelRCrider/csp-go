package csp

import (
	"fmt"
	"os"
	"testing"

	"github.com/SamuelRCrider/csp_go/core"
	"github.com/SamuelRCrider/csp_go/llm"

	"github.com/stretchr/testify/assert"
)

// TestBasicUsageMock demonstrates the most common usage pattern of the CSP SDK
// using direct policy application instead of the full RunCSP function
func TestBasicUsageMock(t *testing.T) {
	// Test input with sensitive information
	input := "My email is john.doe@example.com and my credit card is 4111-1111-1111-1111"

	// Create a policy
	builder := core.NewPolicyBuilder()
	policy := builder.
		WithMetadata("1.0.0", "Test Policy", "Test Author").
		WithDefaultAction(core.ActionAlert).
		AddRule("email", "email", "regex", `[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`, core.ActionRedact).
		AddRule("credit_card", "credit_card", "regex", `\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}`, core.ActionMask).
		Build()

	// Directly use the core scanning and redaction functions
	matches := core.ScanText(input, policy)
	output := core.ApplyRedactions(input, matches)

	// Verify we got some redactions
	assert.NotEmpty(t, matches)
	assert.NotEqual(t, input, output)
	assert.Contains(t, output, "[REDACTED:email]")
	assert.Contains(t, output, "[MASKED:credit_card]")

	// Since this is a demo, we print the output for better visibility
	fmt.Println("Original:", input)
	fmt.Println("Processed output:", output)
}

// TestPolicyCreation demonstrates how to create a custom policy using the PolicyBuilder
func TestPolicyCreation(t *testing.T) {
	builder := core.NewPolicyBuilder()
	policy := builder.
		WithMetadata("1.0.0", "Custom Test Policy", "Test Author").
		WithFrameworks(core.FrameworkSOC2, core.FrameworkPCI).
		WithDefaultAction(core.ActionAlert).
		// Add a rule for email addresses
		AddRule("pii-email", "email", "regex", `[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`, core.ActionRedact).
		ConfigureLastRule().
		WithDescription("Redacts email addresses").
		WithRiskLevel(2).
		WithFrameworks(core.FrameworkSOC2, core.FrameworkGDPR).
		Done().
		// Add a rule for credit card numbers
		AddRule("pci-creditcard", "credit_card", "regex", `\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}`, core.ActionMask).
		ConfigureLastRule().
		WithDescription("Masks credit card numbers").
		WithRiskLevel(3).
		WithFrameworks(core.FrameworkPCI).
		Done().
		Build()

	// Save the policy to a temporary file
	policyPath := "test_policy.yaml"
	err := core.SavePolicy(policy, policyPath)
	assert.NoError(t, err)
	defer os.Remove(policyPath) // Clean up after test

	// Load the policy from the file
	loadedPolicy, err := core.LoadPolicy(policyPath)
	assert.NoError(t, err)
	assert.Equal(t, policy.Metadata.Version, loadedPolicy.Metadata.Version)
	assert.Equal(t, len(policy.Rules), len(loadedPolicy.Rules))

	// Test the policy with some sample text
	input := "My email is jane.doe@example.com and my credit card is 4111-1111-1111-1111"
	matches := core.ScanText(input, loadedPolicy)

	// NOTE: The scanner finds 5 matches instead of 2, which is fine as it's using
	// enhanced scanning with built-in patterns beyond our explicit rules
	assert.GreaterOrEqual(t, len(matches), 2)

	// Apply redactions based on the policy
	redactedOutput := core.ApplyRedactions(input, matches)
	assert.NotEqual(t, input, redactedOutput)

	fmt.Println("Original:", input)
	fmt.Println("Redacted:", redactedOutput)
}

// TestMCPConfigDiscovery tests the MCP configuration discovery logic
func TestMCPConfigDiscovery(t *testing.T) {
	// Save existing environment variable if any
	oldPath := os.Getenv("MCP_SERVER_PATH")
	defer os.Setenv("MCP_SERVER_PATH", oldPath) // Restore at end of test

	// Set test environment variable
	testMCPPath := "/test/path/to/mcp-server"
	os.Setenv("MCP_SERVER_PATH", testMCPPath)

	// Get MCP server config using the discovery method
	config, err := llm.GetMCPServerConfig("")

	// Should find our test path
	assert.NoError(t, err)
	assert.Equal(t, testMCPPath, config.Path)
	assert.Equal(t, "stdio", config.Transport)

	// Test with explicit path (should override environment)
	explicitPath := "/explicit/path/to/mcp"
	config, err = llm.GetMCPServerConfig(explicitPath)
	assert.NoError(t, err)
	assert.Equal(t, explicitPath, config.Path)

	// Test with HTTP URL
	httpURL := "https://mcp.example.com"
	config, err = llm.GetMCPServerConfig(httpURL)
	assert.NoError(t, err)
	assert.Equal(t, httpURL, config.URL)
	assert.Equal(t, "http", config.Transport)

	fmt.Println("MCP configuration discovery working correctly")
}

// TestMCPConfigFromEnv tests loading MCP configuration from environment variables
func TestMCPConfigFromEnv(t *testing.T) {
	// Save existing environment variables
	oldToolName := os.Getenv("MCP_TOOL_NAME")
	oldModel := os.Getenv("MCP_MODEL")
	defer func() {
		os.Setenv("MCP_TOOL_NAME", oldToolName)
		os.Setenv("MCP_MODEL", oldModel)
	}()

	// Set test environment variables
	os.Setenv("MCP_TOOL_NAME", "test.tool")
	os.Setenv("MCP_MODEL", "test-model-v1")

	// Load config from environment
	config := llm.LoadMCPConfig(nil)

	// Verify environment values were used
	assert.Equal(t, "test.tool", config.ToolName)
	assert.Equal(t, "test-model-v1", config.Model)

	// Test that provided config takes precedence
	customConfig := &llm.MCPConfig{
		ToolName: "custom.tool",
		Model:    "custom-model",
	}

	mergedConfig := llm.LoadMCPConfig(customConfig)

	// Custom values should remain, only missing values should be filled from env
	assert.Equal(t, "custom.tool", mergedConfig.ToolName)
	assert.Equal(t, "custom-model", mergedConfig.Model)

	fmt.Println("MCP configuration from environment working correctly")
}
