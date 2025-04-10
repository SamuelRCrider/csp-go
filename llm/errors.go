package llm

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// ErrorCategory defines standardized error categories for SOC 2 audit trails
type ErrorCategory string

const (
	ErrorCategoryAuthentication ErrorCategory = "authentication"
	ErrorCategoryAuthorization  ErrorCategory = "authorization"
	ErrorCategoryValidation     ErrorCategory = "validation"
	ErrorCategoryRateLimit      ErrorCategory = "rate_limit"
	ErrorCategoryDLP            ErrorCategory = "dlp"
	ErrorCategorySystem         ErrorCategory = "system"
	ErrorCategoryTimeout        ErrorCategory = "timeout"
	ErrorCategoryNetwork        ErrorCategory = "network"
	ErrorCategoryModel          ErrorCategory = "model"
)

// CSPError wraps errors with standardized metadata for SOC 2 compliance
type CSPError struct {
	Category    ErrorCategory
	OriginalErr error
	RequestID   string
	Timestamp   time.Time
	Details     map[string]interface{}
}

func (e CSPError) Error() string {
	return fmt.Sprintf("[%s] %s (request: %s)", e.Category, e.OriginalErr.Error(), e.RequestID)
}

func (e CSPError) Unwrap() error {
	return e.OriginalErr
}

// newCSPError creates a new CSPError with standard fields
func newCSPError(category ErrorCategory, err error, requestID string, details map[string]interface{}) CSPError {
	return CSPError{
		Category:    category,
		OriginalErr: err,
		RequestID:   requestID,
		Timestamp:   time.Now(),
		Details:     details,
	}
}

// ErrorReporter handles standardized error reporting for SOC 2 compliance
type ErrorReporter struct {
	logger *log.Logger
}

// NewErrorReporter creates a new error reporter
func NewErrorReporter(logger *log.Logger) *ErrorReporter {
	return &ErrorReporter{
		logger: logger,
	}
}

// ReportError logs an error in SOC 2 compliant format
func (e *ErrorReporter) ReportError(err error) {
	// Extract CSP error metadata if available
	var cspErr CSPError
	details := map[string]interface{}{}

	if errors.As(err, &cspErr) {
		details = map[string]interface{}{
			"category":   string(cspErr.Category),
			"request_id": cspErr.RequestID,
			"timestamp":  cspErr.Timestamp.Format(time.RFC3339),
		}

		// Add any additional details
		for k, v := range cspErr.Details {
			details[k] = v
		}
	}

	// Create structured error log
	logEntry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"event":     "error",
		"error":     err.Error(),
		"details":   details,
	}

	jsonData, err := json.Marshal(logEntry)
	if err != nil {
		e.logger.Printf("Error marshaling error log: %v", err)
		return
	}

	e.logger.Println(string(jsonData))
}

// categorizeError categorizes error based on error message
func categorizeError(err error) ErrorCategory {
	errStr := err.Error()

	if strings.Contains(errStr, "unauthorized") || strings.Contains(errStr, "authentication") {
		return ErrorCategoryAuthentication
	} else if strings.Contains(errStr, "permission") || strings.Contains(errStr, "access denied") {
		return ErrorCategoryAuthorization
	} else if strings.Contains(errStr, "rate limit") || strings.Contains(errStr, "too many requests") {
		return ErrorCategoryRateLimit
	} else if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
		return ErrorCategoryTimeout
	} else if strings.Contains(errStr, "network") || strings.Contains(errStr, "connection") {
		return ErrorCategoryNetwork
	} else if strings.Contains(errStr, "invalid") || strings.Contains(errStr, "validation") {
		return ErrorCategoryValidation
	}

	return ErrorCategorySystem
}
