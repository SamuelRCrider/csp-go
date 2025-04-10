package llm

import (
	"time"
)

// MCPConfig holds configuration for MCP interactions
type MCPConfig struct {
	ToolName     string                 // The MCP tool name to call
	Model        string                 // Model name (e.g., "gpt-4", "claude-3")
	Temperature  float64                // Controls randomness (0.0-1.0)
	MaxTokens    int                    // Maximum tokens to generate
	ExtraParams  map[string]interface{} // Any additional model parameters
	Timeout      time.Duration          // Context timeout for calls
	RetryCount   int                    // Number of retries on failure
	RetryBackoff time.Duration          // Backoff duration between retries

	// SOC 2 Security Features
	EnableDLP          bool             // Data Loss Prevention scanning
	DLPPatterns        []string         // Additional DLP patterns beyond core patterns
	RateLimitEnabled   bool             // Enable rate limiting
	RequestsPerMinute  int              // Max requests per minute (for rate limiting)
	MaxContentSize     int              // Maximum content size in bytes
	AuditLevel         string           // Audit logging level: "minimal", "standard", "verbose"
	Encryption         EncryptionConfig // Encryption settings
	RequestValidation  ValidationConfig // Input validation settings
	ResponseValidation ValidationConfig // Output validation settings
}

// EncryptionConfig holds encryption-related configuration
type EncryptionConfig struct {
	Enabled             bool   // Whether to encrypt sensitive data
	KeySource           string // "env", "file", "kms"
	KeyName             string // Name of the key or environment variable
	EncryptSensitiveLog bool   // Whether to encrypt sensitive parts of logs
}

// ValidationConfig holds validation-related configuration
type ValidationConfig struct {
	Enabled            bool // Whether to validate input/output
	MaxLength          int  // Maximum length of content
	RequireJSONOutput  bool // Whether output should be valid JSON
	DisallowCodeBlocks bool // Whether to disallow code blocks in output
	DisallowURLs       bool // Whether to disallow URLs in content
}

// Conversation represents a sequence of messages
type Conversation struct {
	Messages []Message
	Role     string
}

// Message represents a single message in a conversation
type Message struct {
	Role    string // "system", "user", "assistant"
	Content string
}

// StreamChunk represents a chunk of a streaming response
type StreamChunk struct {
	Data string
	Done bool
}

// CSPAdapter defines the interface for secure LLM interactions
type CSPAdapter interface {
	// Process processes a single input and returns the sanitized output
	Process(input string) (string, error)

	// ProcessStream processes an input and streams the response through a callback
	ProcessStream(input string, callback func(chunk string, done bool) error) error

	// ProcessConversation processes a conversation with a new user message
	ProcessConversation(conv *Conversation, newUserMessage string) (string, error)

	// ProcessSimplePrompt processes a simple system prompt + user prompt combination
	ProcessSimplePrompt(systemPrompt, userPrompt string) (string, error)
}

// ContentPart represents a part of the content for generation
type ContentPart struct {
	Type  string `json:"type"` // e.g., "text", "image"
	Text  string `json:"text,omitempty"`
	Image []byte `json:"image,omitempty"`
	Role  string `json:"role,omitempty"` // e.g., "user", "system"
}

// GenerateOptions contains options for content generation
type GenerateOptions struct {
	Model       string                 `json:"model"`
	Temperature float64                `json:"temperature"`
	MaxTokens   int                    `json:"max_tokens"`
	ExtraParams map[string]interface{} `json:"extra_params,omitempty"`
}

// GenerateResponse contains the response from content generation
type GenerateResponse struct {
	Text       string                 `json:"text"`
	TokenCount int                    `json:"token_count"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// RateLimitIdentifier contains rate limit check results
type RateLimitIdentifier struct {
	Limited   bool
	Count     int
	ResetTime time.Time
}
