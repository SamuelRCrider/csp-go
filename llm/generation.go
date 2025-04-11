package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/SamuelRCrider/csp_go/core"

	"github.com/mark3labs/mcp-go/mcp"
)

// Generate processes content generation with enhanced security features
// It handles input validation, DLP scanning, rate limiting, and comprehensive error handling
func (a *CSPMCPAdapter) Generate(content []ContentPart, options GenerateOptions) (*GenerateResponse, error) {
	// Generate a unique request ID for tracking
	requestID := generateRequestID()
	startTime := time.Now()

	// Log the request initiation
	a.requestLog.LogRequest(requestID, map[string]interface{}{
		"user_role":     a.Ctx.Role,
		"request_id":    requestID,
		"content_parts": len(content),
		"model":         options.Model,
		"operation":     "generate",
	}, "minimal")

	// Validate the request
	if err := validateGenerateRequest(content, options, a.Config.MaxContentSize); err != nil {
		validationErr := newCSPError(ErrorCategoryValidation, err, requestID, nil)
		a.errorReporter.ReportError(validationErr)
		a.requestLog.LogRequest(requestID, map[string]interface{}{
			"error":      "validation_failed",
			"error_type": "validation",
			"error_msg":  err.Error(),
		}, "standard")
		return nil, validationErr
	}

	// Scan for sensitive data if DLP is enabled
	if a.dlpScanner != nil && a.Config.EnableDLP {
		violations, err := scanContentParts(a.dlpScanner, content)
		if err != nil {
			dlpErr := newCSPError(ErrorCategoryDLP, err, requestID, nil)
			a.errorReporter.ReportError(dlpErr)
			return nil, dlpErr
		}

		if len(violations) > 0 {
			dlpErr := newCSPError(ErrorCategoryDLP,
				fmt.Errorf("input contains %d sensitive data pattern(s)", len(violations)),
				requestID,
				map[string]interface{}{"violations": violations})
			a.errorReporter.ReportError(dlpErr)
			a.requestLog.LogRequest(requestID, map[string]interface{}{
				"error":           "dlp_violation",
				"error_type":      "dlp",
				"violation_count": len(violations),
			}, "standard")
			return nil, dlpErr
		}
	}

	// Apply rate limiting if enabled
	if a.rateLimiter != nil && a.Config.RateLimitEnabled {
		// Determine the appropriate identifier for rate limiting
		identifier := checkRateLimit(a.rateLimiter, a.Ctx, requestID)
		if identifier.Limited {
			rateLimitErr := newCSPError(ErrorCategoryRateLimit,
				fmt.Errorf("rate limit exceeded: %d requests (limit: %d)",
					identifier.Count, a.Config.RequestsPerMinute),
				requestID,
				map[string]interface{}{
					"current_count": identifier.Count,
					"limit":         a.Config.RequestsPerMinute,
					"reset_time":    identifier.ResetTime.Format(time.RFC3339),
				})
			a.errorReporter.ReportError(rateLimitErr)
			a.requestLog.LogRequest(requestID, map[string]interface{}{
				"error":         "rate_limit_exceeded",
				"error_type":    "rate_limit",
				"current_count": identifier.Count,
				"limit":         a.Config.RequestsPerMinute,
			}, "standard")
			return nil, rateLimitErr
		}
	}

	// Sanitize the content parts
	sanitizedContent, contentChanges := sanitizeContentParts(content, a.Policy, a.Ctx)

	// Log request details after preprocessing
	a.requestLog.LogRequest(requestID, map[string]interface{}{
		"user_role":            a.Ctx.Role,
		"request_id":           requestID,
		"content_parts":        len(content),
		"model":                options.Model,
		"content_sanitized":    contentChanges > 0,
		"sanitization_changes": contentChanges,
		"input_tokens_est":     estimateInputTokensFromParts(sanitizedContent),
	}, "standard")

	// Set up MCP parameters with model configuration
	modelParams := map[string]interface{}{
		"model":       options.Model,
		"temperature": options.Temperature,
		"max_tokens":  options.MaxTokens,
		"request_id":  requestID,
	}

	// Add any additional parameters from options
	for k, v := range options.ExtraParams {
		modelParams[k] = v
	}

	// Convert content parts to format expected by MCP
	mcpContent := convertContentPartsToMCP(sanitizedContent)
	modelParams["content"] = mcpContent

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), a.Config.Timeout)
	defer cancel()

	// Prepare request to MCP
	request := mcp.CallToolRequest{}
	request.Params.Name = a.Config.ToolName
	request.Params.Arguments = modelParams

	// Call LLM via MCP with retry logic
	var result *mcp.CallToolResult
	var err error
	var lastError error

	for attempt := 0; attempt <= a.Config.RetryCount; attempt++ {
		if attempt > 0 {
			// Wait before retry with exponential backoff
			backoffTime := a.Config.RetryBackoff * time.Duration(1<<(attempt-1))
			time.Sleep(backoffTime)
			a.requestLog.LogRequest(requestID, map[string]interface{}{
				"retry_attempt":  attempt,
				"backoff_ms":     backoffTime.Milliseconds(),
				"previous_error": lastError.Error(),
			}, "verbose")
		}

		result, err = a.Client.CallTool(ctx, request)
		lastError = err

		if err == nil {
			break
		}

		// Don't retry if context is done
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			timeoutErr := newCSPError(ErrorCategoryTimeout,
				fmt.Errorf("generate call timeout or canceled: %w", err),
				requestID, nil)
			a.errorReporter.ReportError(timeoutErr)
			return nil, timeoutErr
		}
	}

	// Handle errors with categorization
	if err != nil {
		errorCategory := categorizeError(err)
		finalErr := newCSPError(errorCategory,
			fmt.Errorf("generate call failed after %d attempts: %w", a.Config.RetryCount+1, err),
			requestID, nil)
		a.errorReporter.ReportError(finalErr)
		return nil, finalErr
	}

	// Process the result
	response, err := processGenerateResult(result, requestID)
	if err != nil {
		resultErr := newCSPError(ErrorCategoryModel,
			fmt.Errorf("error processing generate result: %w", err),
			requestID, nil)
		a.errorReporter.ReportError(resultErr)
		return nil, resultErr
	}

	// Apply response validation and sanitization
	sanitizedResponse, responseChanges := sanitizeResponse(response, a.Policy, a.Ctx, a.Config.ResponseValidation)

	// Calculate metrics
	duration := time.Since(startTime)
	inputTokensEst := estimateInputTokensFromParts(sanitizedContent)
	outputTokensEst := estimateOutputTokens(sanitizedResponse.Text)

	// Log response metrics
	a.requestLog.LogResponse(requestID, map[string]interface{}{
		"request_id":           requestID,
		"duration_ms":          duration.Milliseconds(),
		"input_tokens_est":     inputTokensEst,
		"output_tokens_est":    outputTokensEst,
		"output_chars":         len(sanitizedResponse.Text),
		"response_sanitized":   responseChanges > 0,
		"sanitization_changes": responseChanges,
	}, duration, "standard")

	return sanitizedResponse, nil
}

// Helper functions for the Generate method

// scanContentParts scans all content parts for sensitive data
func scanContentParts(scanner *DLPScanner, content []ContentPart) ([]string, error) {
	allViolations := []string{}

	for _, part := range content {
		if part.Type == "text" {
			violations, err := scanner.ScanContent(part.Text)
			if err != nil {
				return nil, err
			}

			allViolations = append(allViolations, violations...)
		}
		// Note: Image scanning would be implemented separately
	}

	return allViolations, nil
}

// checkRateLimit determines the appropriate identifier for rate limiting
func checkRateLimit(limiter *RateLimiter, ctx *core.Context, requestID string) RateLimitIdentifier {
	// First try to use user ID
	rateLimitKey := ctx.UserID

	// If no user ID, try org ID
	if rateLimitKey == "" {
		rateLimitKey = ctx.OrganizationID
	}

	// If neither, fall back to role or IP
	if rateLimitKey == "" {
		if ctx.Role != "" {
			rateLimitKey = ctx.Role
		} else if ctx.IPAddress != "" {
			rateLimitKey = ctx.IPAddress
		} else {
			// Last resort is a default key
			rateLimitKey = "default_rate_limit_key"
		}
	}

	// Check the rate limit
	limited, count, resetTime := limiter.CheckLimit(rateLimitKey)

	return RateLimitIdentifier{
		Limited:   limited,
		Count:     count,
		ResetTime: resetTime,
	}
}

// sanitizeContentParts applies DLP sanitization to content parts
func sanitizeContentParts(content []ContentPart, policy *core.Policy, ctx *core.Context) ([]ContentPart, int) {
	sanitized := make([]ContentPart, len(content))
	changeCount := 0

	for i, part := range content {
		sanitized[i] = part

		if part.Type == "text" {
			matches := core.ScanTextWithContext(part.Text, policy, ctx)
			sanitizedText := core.ApplyRedactions(part.Text, matches)

			if sanitizedText != part.Text {
				changeCount += len(matches)
				sanitized[i].Text = sanitizedText
			}
		}
	}

	return sanitized, changeCount
}

// convertContentPartsToMCP converts content parts to MCP format
func convertContentPartsToMCP(content []ContentPart) []map[string]interface{} {
	mcpContent := make([]map[string]interface{}, len(content))

	for i, part := range content {
		mcpPart := map[string]interface{}{
			"type": part.Type,
		}

		if part.Role != "" {
			mcpPart["role"] = part.Role
		}

		switch part.Type {
		case "text":
			mcpPart["text"] = part.Text
		case "image":
			mcpPart["image_data"] = part.Image
		}

		mcpContent[i] = mcpPart
	}

	return mcpContent
}

// processGenerateResult extracts and processes result from MCP response
func processGenerateResult(result *mcp.CallToolResult, requestID string) (*GenerateResponse, error) {
	if result.IsError {
		return nil, fmt.Errorf("MCP tool returned an error: %v", result.Result)
	}

	// Extract text from result
	outputStr := ""
	var metadata map[string]interface{}

	if len(result.Content) > 0 {
		for _, content := range result.Content {
			if textContent, ok := content.(mcp.TextContent); ok {
				outputStr += textContent.Text
			}
		}
	}

	if outputStr == "" {
		// Try to extract from result field
		resultJSON, err := json.Marshal(result.Result)
		if err != nil {
			return nil, err
		}

		// Try to parse as object
		var outputObj map[string]interface{}
		if err := json.Unmarshal(resultJSON, &outputObj); err == nil {
			// Check for different response formats
			if output, ok := outputObj["output"]; ok {
				switch v := output.(type) {
				case string:
					outputStr = v
				default:
					outputStr = fmt.Sprintf("%v", v)
				}
			} else if content, ok := outputObj["content"]; ok {
				switch v := content.(type) {
				case string:
					outputStr = v
				default:
					outputStr = fmt.Sprintf("%v", v)
				}
			} else if text, ok := outputObj["text"]; ok {
				switch v := text.(type) {
				case string:
					outputStr = v
				default:
					outputStr = fmt.Sprintf("%v", v)
				}
			} else {
				// If no recognized fields, use the entire JSON
				outputStr = string(resultJSON)
			}

			// Extract any metadata
			if meta, ok := outputObj["metadata"]; ok {
				if metaMap, ok := meta.(map[string]interface{}); ok {
					metadata = metaMap
				}
			}
		} else {
			// If not a JSON object, use the raw string
			outputStr = string(resultJSON)
		}
	}

	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Add request ID to metadata
	metadata["request_id"] = requestID

	// Estimate token count
	tokenCount := estimateOutputTokens(outputStr)

	return &GenerateResponse{
		Text:       outputStr,
		TokenCount: tokenCount,
		Metadata:   metadata,
	}, nil
}

// sanitizeResponse applies validation and DLP to the response
func sanitizeResponse(response *GenerateResponse, policy *core.Policy, ctx *core.Context, validation ValidationConfig) (*GenerateResponse, int) {
	// Create a copy for sanitization
	sanitized := &GenerateResponse{
		Text:       response.Text,
		TokenCount: response.TokenCount,
		Metadata:   make(map[string]interface{}),
	}

	// Copy metadata
	for k, v := range response.Metadata {
		sanitized.Metadata[k] = v
	}

	// Apply length validation
	if validation.Enabled && validation.MaxLength > 0 &&
		len(response.Text) > validation.MaxLength {
		sanitized.Text = response.Text[:validation.MaxLength] + "... [truncated]"
		sanitized.Metadata["truncated"] = true
		sanitized.TokenCount = estimateOutputTokens(sanitized.Text)
	}

	// Apply DLP
	matches := core.ScanTextWithContext(sanitized.Text, policy, ctx)
	if len(matches) > 0 {
		sanitized.Text = core.ApplyRedactions(sanitized.Text, matches)
		sanitized.Metadata["sanitized"] = true
		sanitized.TokenCount = estimateOutputTokens(sanitized.Text)

		// Record types of sanitization performed
		sanitizationTypes := make([]string, 0, len(matches))
		for _, match := range matches {
			sanitizationTypes = append(sanitizationTypes, match.Type)
		}
		sanitized.Metadata["sanitization_types"] = sanitizationTypes

		return sanitized, len(matches)
	}

	return sanitized, 0
}
