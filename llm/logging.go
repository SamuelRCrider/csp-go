package llm

import (
	"encoding/json"
	"log"
	"time"
)

// RequestLogger handles SOC 2 compliant audit logging
type RequestLogger struct {
	logger     *log.Logger
	auditLevel string
}

// NewRequestLogger creates a new request logger
func NewRequestLogger(logger *log.Logger, auditLevel string) *RequestLogger {
	return &RequestLogger{
		logger:     logger,
		auditLevel: auditLevel,
	}
}

// LogRequest logs request details according to audit level
func (l *RequestLogger) LogRequest(requestID string, request map[string]interface{}, level string) {
	if level == "minimal" && l.auditLevel == "minimal" {
		// Skip detailed logging for minimal level
		return
	}

	// Create safe copy of request with sensitive data redacted
	safeCopy := make(map[string]interface{})
	for k, v := range request {
		if k == "api_key" || k == "auth_token" || k == "password" {
			safeCopy[k] = "[REDACTED]"
		} else {
			safeCopy[k] = v
		}
	}

	// Log as JSON
	logEntry := map[string]interface{}{
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"request_id": requestID,
		"event":      "request",
		"level":      level,
		"data":       safeCopy,
	}

	jsonData, err := json.Marshal(logEntry)
	if err != nil {
		l.logger.Printf("Error marshaling log entry: %v", err)
		return
	}

	l.logger.Println(string(jsonData))
}

// LogResponse logs response details according to audit level
func (l *RequestLogger) LogResponse(requestID string, response interface{}, duration time.Duration, level string) {
	if level == "minimal" && l.auditLevel == "minimal" {
		// For minimal logging, just log request ID and status
		l.logger.Printf("Request %s completed in %v", requestID, duration)
		return
	}

	// Log detailed response
	logEntry := map[string]interface{}{
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"request_id":  requestID,
		"event":       "response",
		"level":       level,
		"duration_ms": duration.Milliseconds(),
		"data":        response,
	}

	jsonData, err := json.Marshal(logEntry)
	if err != nil {
		l.logger.Printf("Error marshaling log entry: %v", err)
		return
	}

	l.logger.Println(string(jsonData))
}
