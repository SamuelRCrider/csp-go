package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"samcrider/csp"
	"samcrider/csp/core"
	"samcrider/csp/llm"
)

func main() {
	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Failed to get current working directory: %v\n", err)
		os.Exit(1)
	}

	// Set up paths and config with absolute paths
	mcpServerPath := filepath.Join(cwd, "sample_mcp_server")
	mcpServerSourcePath := filepath.Join(cwd, "examples", "sample_mcp_server.go")

	// Check if MCP server binary exists, if not, compile it
	if _, err := os.Stat(mcpServerPath); os.IsNotExist(err) {
		fmt.Printf("MCP server binary not found at %s\n", mcpServerPath)
		fmt.Println("Compiling from source...")

		cmd := exec.Command("go", "build", "-o", mcpServerPath, mcpServerSourcePath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Printf("Failed to compile MCP server: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Compilation successful!")
	}

	// Make sure the binary is executable
	if err := os.Chmod(mcpServerPath, 0755); err != nil {
		fmt.Printf("Failed to make the server executable: %v\n", err)
		os.Exit(1)
	}

	// Example 1: Configure MCP server globally
	fmt.Println("Example 1: Using global MCP configuration")
	csp.ConfigureMCP(mcpServerPath)

	result1, err := csp.RunCSP("Hello, my name is John Smith and my email is john.smith@example.com", "user")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Result: %s\n\n", result1)
	}

	// Example 2: Use direct configuration
	fmt.Println("Example 2: Using direct MCP configuration")

	// Create custom MCP config
	mcpConfig := &llm.MCPConfig{
		ToolName:    "custom.llm.wrapper",
		Model:       "custom-model-v1",
		Temperature: 0.2,
		MaxTokens:   200,
		Timeout:     time.Second * 10,
		RetryCount:  1,
		EnableDLP:   true,
		AuditLevel:  "verbose",
	}

	result2, err := csp.RunCSPWithConfig(
		"What's the weather like today? My credit card is 4111-1111-1111-1111.",
		"admin",
		mcpServerPath,
		mcpConfig,
	)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Result: %s\n\n", result2)
	}

	// Example 3: Direct use of policy for redaction without LLM
	fmt.Println("Example 3: Direct policy application without LLM")

	// Create a custom policy
	builder := core.NewPolicyBuilder()
	policy := builder.
		WithMetadata("1.0.0", "Demo Policy", "CSP SDK").
		WithDefaultAction(core.ActionAlert).
		AddRule("ssn", "ssn", "regex", `\d{3}-\d{2}-\d{4}`, core.ActionRedact).
		AddRule("api_key", "api_key", "regex", `(api_key|api_secret|access_token)[\s:=]+[a-zA-Z0-9_\-]{20,}`, core.ActionRedact).
		Build()

	// Sample input with sensitive data
	input := "My SSN is 123-45-6789 and my API key is api_key=abcd1234efgh5678ijkl90"

	// Scan and apply redactions
	matches := core.ScanText(input, policy)
	redacted := core.ApplyRedactions(input, matches)

	fmt.Printf("Original: %s\n", input)
	fmt.Printf("Redacted: %s\n", redacted)
}
