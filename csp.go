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

// RunCSPStream processes input with the CSP pipeline and streams the output
// via the provided callback function
func RunCSPStream(input string, role string, callback func(chunk string, done bool) error) error {
	// Load policy
	policy, err := core.LoadPolicy("config/default_policy.yaml")
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	// Create user context
	ctx := &core.Context{Role: role}

	// Initialize MCP adapter with auto-discovery of servers
	adapter, err := llm.NewCSPMCPAdapter(ctx, "", policy, &llm.MCPConfig{})
	if err != nil {
		return fmt.Errorf("failed to initialize MCP adapter: %w", err)
	}

	// Process streaming input
	if err := adapter.ProcessStream(input, callback); err != nil {
		return fmt.Errorf("CSP streaming failed: %w", err)
	}

	return nil
}

// RunCSPStreamWithConfig processes input with the CSP pipeline using custom configuration
// and streams the output via the provided callback function
func RunCSPStreamWithConfig(input string, role string, mcpServerPath string, config *llm.MCPConfig, callback func(chunk string, done bool) error) error {
	// Load policy
	policy, err := core.LoadPolicy("config/default_policy.yaml")
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	// Create user context
	ctx := &core.Context{Role: role}

	// Initialize MCP adapter with provided configuration
	adapter, err := llm.NewCSPMCPAdapter(ctx, mcpServerPath, policy, config)
	if err != nil {
		return fmt.Errorf("failed to initialize MCP adapter: %w", err)
	}

	// Process streaming input
	if err := adapter.ProcessStream(input, callback); err != nil {
		return fmt.Errorf("CSP streaming failed: %w", err)
	}

	return nil
}

// Message represents a single message in a conversation
type Message struct {
	Role    string
	Content string
}

// Conversation represents a multi-turn conversation
type Conversation struct {
	Role     string
	Messages []Message
}

// NewConversation creates a new conversation with the specified role
func NewConversation(role string) *Conversation {
	return &Conversation{
		Role:     role,
		Messages: []Message{},
	}
}

// AddSystemMessage adds a system message to the conversation
func (c *Conversation) AddSystemMessage(content string) {
	c.Messages = append(c.Messages, Message{Role: "system", Content: content})
}

// AddUserMessage adds a user message to the conversation
func (c *Conversation) AddUserMessage(content string) {
	c.Messages = append(c.Messages, Message{Role: "user", Content: content})
}

// AddAssistantMessage adds an assistant message to the conversation
func (c *Conversation) AddAssistantMessage(content string) {
	c.Messages = append(c.Messages, Message{Role: "assistant", Content: content})
}

// RunCSPConversation processes a new user message in a conversation with the CSP pipeline
func RunCSPConversation(conv *Conversation, userMessage string) (string, error) {
	// Load policy
	policy, err := core.LoadPolicy("config/default_policy.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to load policy: %w", err)
	}

	// Create user context
	ctx := &core.Context{Role: conv.Role}

	// Initialize MCP adapter with auto-discovery of servers
	adapter, err := llm.NewCSPMCPAdapter(ctx, "", policy, &llm.MCPConfig{})
	if err != nil {
		return "", fmt.Errorf("failed to initialize MCP adapter: %w", err)
	}

	// Convert our conversation to adapter's internal format
	adapterConv := &llm.Conversation{
		Role:     conv.Role,
		Messages: []llm.Message{},
	}

	for _, msg := range conv.Messages {
		adapterConv.Messages = append(adapterConv.Messages, llm.Message{
			Role:    msg.Role,
			Content: msg.Content,
		})
	}

	// Process conversation
	output, err := adapter.ProcessConversation(adapterConv, userMessage)
	if err != nil {
		return "", fmt.Errorf("CSP conversation processing failed: %w", err)
	}

	// Update the conversation with the new user message and assistant response
	conv.AddUserMessage(userMessage)
	conv.AddAssistantMessage(output)

	return output, nil
}

// RunCSPConversationWithConfig processes a new user message in a conversation with custom configuration
func RunCSPConversationWithConfig(conv *Conversation, userMessage string, mcpServerPath string, config *llm.MCPConfig) (string, error) {
	// Load policy
	policy, err := core.LoadPolicy("config/default_policy.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to load policy: %w", err)
	}

	// Create user context
	ctx := &core.Context{Role: conv.Role}

	// Initialize MCP adapter with provided configuration
	adapter, err := llm.NewCSPMCPAdapter(ctx, mcpServerPath, policy, config)
	if err != nil {
		return "", fmt.Errorf("failed to initialize MCP adapter: %w", err)
	}

	// Convert our conversation to adapter's internal format
	adapterConv := &llm.Conversation{
		Role:     conv.Role,
		Messages: []llm.Message{},
	}

	for _, msg := range conv.Messages {
		adapterConv.Messages = append(adapterConv.Messages, llm.Message{
			Role:    msg.Role,
			Content: msg.Content,
		})
	}

	// Process conversation
	output, err := adapter.ProcessConversation(adapterConv, userMessage)
	if err != nil {
		return "", fmt.Errorf("CSP conversation processing failed: %w", err)
	}

	// Update the conversation with the new user message and assistant response
	conv.AddUserMessage(userMessage)
	conv.AddAssistantMessage(output)

	return output, nil
}

// RunCSPWithMetadata processes input with the CSP pipeline using client-supplied metadata
func RunCSPWithMetadata(input string, role string, metadata map[string]interface{}) (string, error) {
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

	// Process with metadata
	output, err := adapter.ProcessWithMetadata(input, metadata)
	if err != nil {
		return "", fmt.Errorf("CSP processing with metadata failed: %w", err)
	}

	return output, nil
}

// RunCSPSimplePrompt processes a system prompt + user prompt combination
func RunCSPSimplePrompt(systemPrompt string, userPrompt string, role string) (string, error) {
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

	// Process simple prompt
	output, err := adapter.ProcessSimplePrompt(systemPrompt, userPrompt)
	if err != nil {
		return "", fmt.Errorf("CSP simple prompt processing failed: %w", err)
	}

	return output, nil
}
