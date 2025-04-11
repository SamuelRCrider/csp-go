package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/SamuelRCrider/csp-go/core"

	"github.com/mark3labs/mcp-go/mcp"
)

// Process handles input sanitization, LLM call via MCP, and output filtering
func (a *CSPMCPAdapter) Process(input string) (string, error) {
	// Generate a unique request ID for tracking
	requestID := generateRequestID()
	startTime := time.Now()

	// Initialize request details for logging
	requestDetails := map[string]interface{}{
		"user_role":   a.Ctx.Role,
		"input_chars": len(input),
		"request_id":  requestID,
	}

	// Log the request (minimal info at this stage)
	a.requestLog.LogRequest(requestID, requestDetails, "minimal")

	// 1. Validate input
	if a.validator != nil && a.Config.RequestValidation.Enabled {
		if err := a.validator.ValidateInput(input); err != nil {
			validationErr := newCSPError(ErrorCategoryValidation, err, requestID, nil)
			a.errorReporter.ReportError(validationErr)
			return "", validationErr
		}
		requestDetails["validation_passed"] = true
	}

	// 2. Scan for sensitive data using DLP if enabled
	if a.dlpScanner != nil && a.Config.EnableDLP {
		violations, err := a.dlpScanner.ScanContent(input)
		if err != nil {
			dlpErr := newCSPError(ErrorCategoryDLP, err, requestID, nil)
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

	// Pre-process with core DLP and policy redaction
	matches := core.ScanTextWithContext(input, a.Policy, a.Ctx)
	sanitized := core.ApplyRedactions(input, matches)

	// Update request details with sanitization info
	requestDetails["input_sanitized"] = len(matches) > 0
	requestDetails["sensitive_matches"] = len(matches)

	// Log the transformation with full details
	if err := core.LogEvent(core.AuditLog{
		UserRole:     a.Ctx.Role,
		Input:        input,
		Transformed:  sanitized,
		Matches:      matches,
		ActionSource: "pre-request",
	}); err != nil {
		// Log but don't fail on logging errors
		fmt.Printf("Warning: Failed to log pre-request event: %v\n", err)
	}

	// Log full request details
	a.requestLog.LogRequest(requestID, requestDetails, "standard")

	// Prepare parameters with model configuration
	params := map[string]interface{}{
		"input":       sanitized,
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
			fmt.Errorf("MCP call failed after %d attempts: %w", a.Config.RetryCount+1, err),
			requestID, nil)
		a.errorReporter.ReportError(finalErr)
		return "", finalErr
	}

	// Check if there was an error in the result
	if result.IsError {
		resultErr := newCSPError(ErrorCategoryModel,
			fmt.Errorf("MCP tool returned an error: %v", result.Result),
			requestID, nil)
		a.errorReporter.ReportError(resultErr)
		return "", resultErr
	}

	// Decode output - MCP response needs to be extracted from result
	outputStr := ""
	if len(result.Content) > 0 {
		// Try to extract text content
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
						// Try to convert to string
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

	// Post-process the output
	finalOutput := core.PostScanAndRedact(outputStr, a.Policy, a.Ctx)

	// Calculate metrics
	duration := time.Since(startTime)
	inputTokensEst := estimateInputTokens(input)
	outputTokensEst := estimateOutputTokens(finalOutput)

	// Log response metrics
	responseDetails := map[string]interface{}{
		"request_id":        requestID,
		"duration_ms":       duration.Milliseconds(),
		"input_tokens_est":  inputTokensEst,
		"output_tokens_est": outputTokensEst,
		"output_chars":      len(finalOutput),
	}

	// Log successful response
	a.requestLog.LogResponse(requestID, responseDetails, duration, "standard")

	// Log post-processing
	if err := core.LogEvent(core.AuditLog{
		UserRole:     a.Ctx.Role,
		Input:        outputStr,
		Transformed:  finalOutput,
		Matches:      core.ScanTextWithContext(outputStr, a.Policy, a.Ctx),
		ActionSource: "post-response",
	}); err != nil {
		fmt.Printf("Warning: Failed to log post-response event: %v\n", err)
	}

	return finalOutput, nil
}
