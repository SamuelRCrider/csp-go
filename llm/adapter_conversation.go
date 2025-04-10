package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"samcrider/csp/core"

	"github.com/mark3labs/mcp-go/mcp"
)

// ProcessConversation handles a conversation with security checks
func (a *CSPMCPAdapter) ProcessConversation(conv *Conversation, newUserMessage string) (string, error) {
	// Generate a unique request ID for tracking
	requestID := generateRequestID()
	startTime := time.Now()

	// Initialize request details for logging
	requestDetails := map[string]interface{}{
		"user_role":         a.Ctx.Role,
		"input_chars":       len(newUserMessage),
		"request_id":        requestID,
		"conversation_msgs": len(conv.Messages),
		"conversation_type": "multi_turn",
	}

	// Log the request (minimal info at this stage)
	a.requestLog.LogRequest(requestID, requestDetails, "minimal")

	// 1. Validate input
	if a.validator != nil && a.Config.RequestValidation.Enabled {
		if err := a.validator.ValidateInput(newUserMessage); err != nil {
			validationErr := newCSPError(ErrorCategoryValidation, err, requestID, nil)
			a.errorReporter.ReportError(validationErr)
			return "", validationErr
		}
		requestDetails["validation_passed"] = true
	}

	// 2. Scan for sensitive data in the new message using DLP if enabled
	if a.dlpScanner != nil && a.Config.EnableDLP {
		violations, err := a.dlpScanner.ScanContent(newUserMessage)
		if err != nil {
			dlpErr := newCSPError(ErrorCategoryDLP,
				fmt.Errorf("DLP scanning error: %w", err),
				requestID, nil)
			a.errorReporter.ReportError(dlpErr)
			return "", dlpErr
		}

		if len(violations) > 0 {
			dlpErr := newCSPError(ErrorCategoryDLP,
				fmt.Errorf("input contains %d sensitive data pattern(s)", len(violations)),
				requestID,
				map[string]interface{}{"violations": violations})
			a.errorReporter.ReportError(dlpErr)
			return "", dlpErr
		}

		requestDetails["dlp_passed"] = true
	}

	// 3. Check rate limit if enabled
	if a.rateLimiter != nil && a.Config.RateLimitEnabled {
		// Determine rate limit key - can be user ID, role, etc.
		rateLimitKey := a.Ctx.Role // Using role as default identifier
		if rateLimitKey == "" {
			rateLimitKey = "default"
		}

		limited, count, resetTime := a.rateLimiter.CheckLimit(rateLimitKey)
		if limited {
			rateLimitErr := newCSPError(ErrorCategoryRateLimit,
				fmt.Errorf("rate limit exceeded: %d requests (limit: %d)",
					count, a.Config.RequestsPerMinute),
				requestID,
				map[string]interface{}{
					"current_count": count,
					"limit":         a.Config.RequestsPerMinute,
					"reset_time":    resetTime.Format(time.RFC3339),
				})
			a.errorReporter.ReportError(rateLimitErr)
			return "", rateLimitErr
		}

		requestDetails["rate_limit_count"] = count
	}

	// Apply DLP to the new message
	matches := core.ScanTextWithContext(newUserMessage, a.Policy, a.Ctx)
	sanitizedMessage := core.ApplyRedactions(newUserMessage, matches)

	// Create a copy of the conversation with sanitized history
	sanitizedConv := &Conversation{
		Role:     conv.Role,
		Messages: make([]Message, len(conv.Messages)),
	}

	// Copy and sanitize any existing messages in conversation history
	for i, msg := range conv.Messages {
		sanitizedContent := msg.Content
		if msg.Role == "user" {
			// Only sanitize user messages
			contentMatches := core.ScanTextWithContext(msg.Content, a.Policy, a.Ctx)
			sanitizedContent = core.ApplyRedactions(msg.Content, contentMatches)
		}
		sanitizedConv.Messages[i] = Message{
			Role:    msg.Role,
			Content: sanitizedContent,
		}
	}

	// Add the new sanitized message
	sanitizedConv.Messages = append(sanitizedConv.Messages, Message{
		Role:    "user",
		Content: sanitizedMessage,
	})

	// Update request details with sanitization info
	requestDetails["input_sanitized"] = len(matches) > 0
	requestDetails["sensitive_matches"] = len(matches)

	// Log the transformation
	if err := core.LogEvent(core.AuditLog{
		UserRole:     a.Ctx.Role,
		Input:        newUserMessage,
		Transformed:  sanitizedMessage,
		Matches:      matches,
		ActionSource: "pre-request-conversation",
	}); err != nil {
		fmt.Printf("Warning: Failed to log pre-request-conversation event: %v\n", err)
	}

	// Log full request details
	a.requestLog.LogRequest(requestID, requestDetails, "standard")

	// Convert conversation to format expected by MCP
	mcpMessages := []map[string]string{}
	for _, msg := range sanitizedConv.Messages {
		mcpMessages = append(mcpMessages, map[string]string{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}

	// Prepare parameters for MCP
	params := map[string]interface{}{
		"messages":    mcpMessages,
		"model":       a.Config.Model,
		"temperature": a.Config.Temperature,
		"max_tokens":  a.Config.MaxTokens,
		"request_id":  requestID,
	}

	// Add any extra parameters
	for k, v := range a.Config.ExtraParams {
		params[k] = v
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), a.Config.Timeout)
	defer cancel()

	// Prepare request
	request := mcp.CallToolRequest{}
	request.Params.Name = a.Config.ToolName
	request.Params.Arguments = params

	// Call LLM via MCP with retries
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
				fmt.Errorf("MCP call timeout or canceled: %w", err),
				requestID, nil)
			a.errorReporter.ReportError(timeoutErr)
			return "", timeoutErr
		}
	}

	if err != nil {
		// Categorize error type for better reporting
		errorCategory := categorizeError(err)
		finalErr := newCSPError(errorCategory,
			fmt.Errorf("MCP conversation call failed after %d attempts: %w", a.Config.RetryCount+1, err),
			requestID, nil)
		a.errorReporter.ReportError(finalErr)
		return "", finalErr
	}

	// Extract response content
	outputStr := ""
	if len(result.Content) > 0 {
		for _, content := range result.Content {
			if textContent, ok := content.(mcp.TextContent); ok {
				outputStr += textContent.Text
			}
		}
	} else {
		// Try to get output from result field
		resultJSON, err := json.Marshal(result.Result)
		if err == nil {
			// Try to parse as object with output field
			var outputObj map[string]interface{}
			if json.Unmarshal(resultJSON, &outputObj) == nil {
				if output, ok := outputObj["output"]; ok {
					// Convert to string if possible
					switch v := output.(type) {
					case string:
						outputStr = v
					default:
						outputStr = fmt.Sprintf("%v", v)
					}
				} else if content, ok := outputObj["content"]; ok {
					// Some APIs return content instead of output
					switch v := content.(type) {
					case string:
						outputStr = v
					default:
						outputStr = fmt.Sprintf("%v", v)
					}
				}
			} else {
				// If not a map, use the raw JSON string
				outputStr = string(resultJSON)
			}
		}
	}

	// Validate output if enabled
	if a.validator != nil && a.Config.ResponseValidation.Enabled {
		if a.Config.ResponseValidation.MaxLength > 0 && len(outputStr) > a.Config.ResponseValidation.MaxLength {
			outputStr = outputStr[:a.Config.ResponseValidation.MaxLength] + "... [truncated]"
		}
	}

	// Post-process the output for DLP
	finalOutput := core.PostScanAndRedact(outputStr, a.Policy, a.Ctx)

	// Update conversation with assistant response
	conv.Messages = append(conv.Messages, Message{
		Role:    "user",
		Content: newUserMessage,
	})

	conv.Messages = append(conv.Messages, Message{
		Role:    "assistant",
		Content: finalOutput,
	})

	// Calculate metrics
	duration := time.Since(startTime)
	inputTokensEst := estimateConversationTokens(sanitizedConv)
	outputTokensEst := estimateOutputTokens(finalOutput)

	// Log response metrics
	responseDetails := map[string]interface{}{
		"request_id":          requestID,
		"duration_ms":         duration.Milliseconds(),
		"input_tokens_est":    inputTokensEst,
		"output_tokens_est":   outputTokensEst,
		"output_chars":        len(finalOutput),
		"conversation_length": len(conv.Messages),
	}

	// Log successful response
	a.requestLog.LogResponse(requestID, responseDetails, duration, "standard")

	// Log post-processing
	if err := core.LogEvent(core.AuditLog{
		UserRole:     a.Ctx.Role,
		Input:        outputStr,
		Transformed:  finalOutput,
		Matches:      core.ScanTextWithContext(outputStr, a.Policy, a.Ctx),
		ActionSource: "post-response-conversation",
	}); err != nil {
		fmt.Printf("Warning: Failed to log post-response-conversation event: %v\n", err)
	}

	return finalOutput, nil
}
