package csp

import (
	"fmt"
	"os"

	"github.com/SamuelRCrider/csp-go/core"
	"github.com/SamuelRCrider/csp-go/llm"
)

// ConfigureMCPServer configures the MCP server to use for all CSP operations
// It can be called once at startup to set the MCP server details
func ConfigureMCPServer(serverPath string) {
	os.Setenv("MCP_SERVER_PATH", serverPath)
}

// RunCSP runs the full context security pipeline for a given input and role
func RunCSP(input string, role string) (string, error) {
	// Load policy
	policy, err := core.LoadPolicy("config/default_policy.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to load policy: %w", err)
	}

	// Create user context
	ctx := &core.Context{Role: role}

	// Initialize MCP adapter with auto-discovery of servers
	adapter, err := llm.NewCSPMCPAdapter(ctx, "", policy, &llm.MCPConfig{})
	if err != nil {
		return "", fmt.Errorf("failed to initialize MCP adapter: %w", err)
	}

	// Process input
	output, err := adapter.Process(input)
	if err != nil {
		return "", fmt.Errorf("CSP processing failed: %w", err)
	}

	return output, nil
}

// RunCSPWithConfig runs the full CSP pipeline with custom configuration
func RunCSPWithConfig(input string, role string, mcpServerPath string, config *llm.MCPConfig) (string, error) {
	// Load policy
	policy, err := core.LoadPolicy("config/default_policy.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to load policy: %w", err)
	}

	// Create user context
	ctx := &core.Context{Role: role}

	// Initialize MCP adapter with provided configuration
	adapter, err := llm.NewCSPMCPAdapter(ctx, mcpServerPath, policy, config)
	if err != nil {
		return "", fmt.Errorf("failed to initialize MCP adapter: %w", err)
	}

	// Process input
	output, err := adapter.Process(input)
	if err != nil {
		return "", fmt.Errorf("CSP processing failed: %w", err)
	}

	return output, nil
}
