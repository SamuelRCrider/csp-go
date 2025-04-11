package llm

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/SamuelRCrider/csp-go/core"

	"github.com/mark3labs/mcp-go/client"
)

// CSPMCPAdapter adapts CSP to work with MCP
type CSPMCPAdapter struct {
	Client *client.StdioMCPClient
	Policy *core.Policy
	Ctx    *core.Context
	Config MCPConfig

	// SOC 2 compliance features
	rateLimiter   *RateLimiter
	requestLog    *RequestLogger
	dlpScanner    *DLPScanner
	validator     *RequestValidator
	errorReporter *ErrorReporter
}

// NewCSPMCPAdapter initializes a new MCP adapter with configuration
func NewCSPMCPAdapter(ctx *core.Context, serverPath string, policy *core.Policy, config *MCPConfig) (*CSPMCPAdapter, error) {
	// Get MCP server configuration
	serverConfig, err := GetMCPServerConfig(serverPath)
	if err != nil {
		return nil, fmt.Errorf("failed to configure MCP server: %w", err)
	}

	// Load and merge configuration
	config = LoadMCPConfig(config)

	// Add default SOC 2 security settings if not specified
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	// Ensure security settings are initialized with defaults if not provided
	if config.EnableDLP && config.DLPPatterns == nil {
		config.DLPPatterns = []string{}
	}

	if config.RateLimitEnabled && config.RequestsPerMinute == 0 {
		config.RequestsPerMinute = 60 // Default 60 rpm
	}

	if config.AuditLevel == "" {
		config.AuditLevel = "standard"
	}

	if config.RequestValidation.Enabled && config.RequestValidation.MaxLength == 0 {
		config.RequestValidation.MaxLength = 16384 // 16KB
	}

	if config.ResponseValidation.Enabled && config.ResponseValidation.MaxLength == 0 {
		config.ResponseValidation.MaxLength = 65536 // 64KB
	}

	if config.MaxContentSize == 0 {
		config.MaxContentSize = 32768 // 32KB
	}

	// Create appropriate MCP client based on transport type
	var mcpClient *client.StdioMCPClient
	switch serverConfig.Transport {
	case "stdio":
		// MCP client expects nil or []string for options
		var opts []string
		if len(serverConfig.Options) > 0 {
			// Convert map to slice of "key=value" strings
			opts = make([]string, 0, len(serverConfig.Options))
			for k, v := range serverConfig.Options {
				opts = append(opts, fmt.Sprintf("%s=%v", k, v))
			}
		}
		mcpClient, err = client.NewStdioMCPClient(serverConfig.Path, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create MCP stdio client: %w", err)
		}
	case "http":
		// Note: Current MCP Go client doesn't support HTTP transport directly
		// This would need to be implemented or a different client library used
		return nil, fmt.Errorf("HTTP transport not currently supported by this implementation")
	default:
		return nil, fmt.Errorf("unsupported MCP transport type: %s", serverConfig.Transport)
	}

	// Create logger
	logger := log.New(os.Stdout, "[CSP] ", log.LstdFlags)

	// Initialize rate limiter if enabled
	var rateLimiter *RateLimiter
	if config.RateLimitEnabled {
		rateLimiter = NewRateLimiter(config.RequestsPerMinute, 1*time.Minute)
	}

	// Initialize DLP scanner if enabled
	var dlpScanner *DLPScanner
	if config.EnableDLP {
		dlpScanner, err = NewDLPScanner(config.DLPPatterns, policy)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize DLP scanner: %w", err)
		}
	}

	// Initialize request logger
	requestLogger := NewRequestLogger(logger, config.AuditLevel)

	// Initialize request validator
	requestValidator := NewRequestValidator(config.RequestValidation)

	// Initialize error reporter
	errorReporter := NewErrorReporter(logger)

	adapter := &CSPMCPAdapter{
		Client:        mcpClient,
		Policy:        policy,
		Ctx:           ctx,
		Config:        *config,
		rateLimiter:   rateLimiter,
		requestLog:    requestLogger,
		dlpScanner:    dlpScanner,
		validator:     requestValidator,
		errorReporter: errorReporter,
	}

	logger.Printf("CSP MCP Adapter initialized with server: %s, security features: DLP=%v, RateLimit=%v, AuditLevel=%s",
		serverConfig.Path, config.EnableDLP, config.RateLimitEnabled, config.AuditLevel)

	return adapter, nil
}

// ProcessSimplePrompt processes a simple system prompt + user prompt combination
func (a *CSPMCPAdapter) ProcessSimplePrompt(systemPrompt, userPrompt string) (string, error) {
	// Create a conversation with system and user messages
	conv := &Conversation{
		Role: a.Ctx.Role,
		Messages: []Message{
			{
				Role:    "system",
				Content: systemPrompt,
			},
		},
	}

	// Process as a conversation
	return a.ProcessConversation(conv, userPrompt)
}

// ProcessWithMetadata allows processing with client-supplied metadata (for tracking/telemetry)
func (a *CSPMCPAdapter) ProcessWithMetadata(input string, metadata map[string]interface{}) (string, error) {
	// Generate a unique request ID for tracking
	requestID := generateRequestID()
	startTime := time.Now()

	// Initialize request details for logging
	requestDetails := map[string]interface{}{
		"user_role":   a.Ctx.Role,
		"input_chars": len(input),
		"request_id":  requestID,
	}

	// Add client metadata
	for k, v := range metadata {
		requestDetails["client_"+k] = v
	}

	// Log the request with the metadata
	a.requestLog.LogRequest(requestID, requestDetails, "minimal")

	// Delegate to standard process method
	result, err := a.Process(input)

	// If successful, log the metadata with the response
	if err == nil {
		a.requestLog.LogResponse(requestID, map[string]interface{}{
			"client_metadata": metadata,
			"success":         true,
			"duration_ms":     time.Since(startTime).Milliseconds(),
		}, time.Since(startTime), "standard")
	}

	return result, err
}

// wrapError wraps an error with category and standardized metadata
func (a *CSPMCPAdapter) wrapError(category ErrorCategory, err error) CSPError {
	requestID := generateRequestID()
	return newCSPError(category, err, requestID, nil)
}
