package core

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"samcrider/csp/utils"
	"sync"
	"time"
)

// AuditLogLevel defines the verbosity of audit logging
type AuditLogLevel string

const (
	// AuditLogLevelMinimal logs only essential security events
	AuditLogLevelMinimal AuditLogLevel = "minimal"

	// AuditLogLevelStandard logs security events with moderate detail
	AuditLogLevelStandard AuditLogLevel = "standard"

	// AuditLogLevelVerbose logs all details including content
	AuditLogLevelVerbose AuditLogLevel = "verbose"
)

// AuditLogSeverity defines the severity of audit log events
type AuditLogSeverity string

const (
	// SeverityInfo for normal operations
	SeverityInfo AuditLogSeverity = "info"

	// SeverityWarning for potential security issues
	SeverityWarning AuditLogSeverity = "warning"

	// SeverityError for security violations or errors
	SeverityError AuditLogSeverity = "error"

	// SeverityCritical for severe security breaches
	SeverityCritical AuditLogSeverity = "critical"
)

// AuditLog represents a security audit log entry with SOC 2 required fields
type AuditLog struct {
	// Core fields for traceability
	RequestID    string           `json:"request_id"`
	Timestamp    string           `json:"timestamp"`
	EventType    string           `json:"event_type"`
	ActionSource string           `json:"action_source"` // e.g. "pre-request", "post-response"
	Severity     AuditLogSeverity `json:"severity"`

	// User context
	UserRole  string `json:"user_role,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`

	// Processing information
	Input       string              `json:"input,omitempty"`
	Transformed string              `json:"transformed,omitempty"`
	Matches     []utils.MatchResult `json:"matches,omitempty"`

	// Compliance fields
	ComplianceFlags map[string]bool   `json:"compliance_flags,omitempty"` // e.g. "gdpr_compliant": true
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// AuditLogger manages SOC 2 compliant audit logging
type AuditLogger struct {
	mu            sync.Mutex
	logPath       string
	level         AuditLogLevel
	writer        io.Writer
	rotationSize  int64 // Size in bytes after which logs should rotate
	currentSize   int64
	logRetention  int // Number of days to retain logs
	initialized   bool
	enableConsole bool
}

// Global default logger
var defaultLogger *AuditLogger
var loggerOnce sync.Once

// GetAuditLogger returns the singleton audit logger instance
func GetAuditLogger() *AuditLogger {
	loggerOnce.Do(func() {
		// Default to writing to audit.log in the current directory
		defaultLogger = &AuditLogger{
			logPath:       "audit.log",
			level:         AuditLogLevelStandard,
			rotationSize:  100 * 1024 * 1024, // 100MB default rotation size
			logRetention:  90,                // 90 days default retention
			enableConsole: true,
		}
		defaultLogger.initialize()
	})

	return defaultLogger
}

// ConfigureLogger configures the audit logger with specific settings
func ConfigureLogger(path string, level AuditLogLevel, rotationSize int64, retention int, enableConsole bool) error {
	logger := GetAuditLogger()

	logger.mu.Lock()
	defer logger.mu.Unlock()

	// Update configuration
	logger.logPath = path
	logger.level = level
	logger.rotationSize = rotationSize
	logger.logRetention = retention
	logger.enableConsole = enableConsole

	// Re-initialize with new settings
	return logger.initialize()
}

// initialize the logger with current settings
func (l *AuditLogger) initialize() error {
	// Create log directory if it doesn't exist
	dir := filepath.Dir(l.logPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}
	}

	// Open log file for appending
	f, err := os.OpenFile(l.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	// Get current file size for rotation tracking
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("failed to get log file info: %w", err)
	}

	l.currentSize = info.Size()

	// If console logging is enabled, use a multiwriter
	if l.enableConsole {
		l.writer = io.MultiWriter(f, os.Stdout)
	} else {
		l.writer = f
	}

	l.initialized = true
	return nil
}

// maybeRotateLog checks if log rotation is needed and performs it if so
func (l *AuditLogger) maybeRotateLog() error {
	if l.currentSize >= l.rotationSize {
		// Close current log file
		if closer, ok := l.writer.(io.Closer); ok {
			closer.Close()
		}

		// Rotate log file
		timestamp := time.Now().Format("20060102-150405")
		rotatedPath := fmt.Sprintf("%s.%s", l.logPath, timestamp)

		if err := os.Rename(l.logPath, rotatedPath); err != nil {
			return fmt.Errorf("failed to rotate log file: %w", err)
		}

		// Cleanup old logs
		l.cleanupOldLogs()

		// Reinitialize logger with new file
		return l.initialize()
	}

	return nil
}

// cleanupOldLogs removes log files older than the retention period
func (l *AuditLogger) cleanupOldLogs() {
	dir := filepath.Dir(l.logPath)
	base := filepath.Base(l.logPath)

	cutoffTime := time.Now().AddDate(0, 0, -l.logRetention)

	files, err := filepath.Glob(filepath.Join(dir, base+".*"))
	if err != nil {
		return
	}

	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoffTime) {
			os.Remove(file)
		}
	}
}

// LogEvent logs an audit event with the specified parameters
func (l *AuditLogger) LogEvent(log AuditLog) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.initialized {
		if err := l.initialize(); err != nil {
			return err
		}
	}

	// Check if rotation is needed
	if err := l.maybeRotateLog(); err != nil {
		return err
	}

	// Set timestamp if not already set
	if log.Timestamp == "" {
		log.Timestamp = time.Now().Format(time.RFC3339Nano)
	}

	// Generate a request ID if not provided
	if log.RequestID == "" {
		log.RequestID = fmt.Sprintf("%d-%x", time.Now().UnixNano(), time.Now().Nanosecond())
	}

	// Apply log level filtering
	if l.level == AuditLogLevelMinimal && log.Severity == SeverityInfo {
		// Skip detailed info logs in minimal mode
		return nil
	}

	// Redact sensitive data in standard mode
	if l.level == AuditLogLevelStandard {
		// Only include first 100 chars of content in standard mode
		if len(log.Input) > 100 {
			log.Input = log.Input[:100] + "... [truncated]"
		}
		if len(log.Transformed) > 100 {
			log.Transformed = log.Transformed[:100] + "... [truncated]"
		}
	}

	// In minimal mode, remove content completely
	if l.level == AuditLogLevelMinimal {
		log.Input = "[redacted]"
		log.Transformed = "[redacted]"
	}

	// Convert to JSON
	entry, err := json.Marshal(log)
	if err != nil {
		return fmt.Errorf("failed to marshal log entry: %w", err)
	}

	// Write to log file
	n, err := fmt.Fprintln(l.writer, string(entry))
	if err != nil {
		return fmt.Errorf("failed to write to log: %w", err)
	}

	// Update current size
	l.currentSize += int64(n)

	return nil
}

// LogEvent appends an audit event to audit.log in JSONL format (legacy function)
func LogEvent(log AuditLog) error {
	// Set severity if not set
	if log.Severity == "" {
		log.Severity = SeverityInfo
	}

	// Use the singleton logger
	return GetAuditLogger().LogEvent(log)
}

// LogSecurityEvent is a helper function to log security-related events
func LogSecurityEvent(requestID, eventType string, severity AuditLogSeverity, userRole string, metadata map[string]string) error {
	log := AuditLog{
		RequestID:    requestID,
		Timestamp:    time.Now().Format(time.RFC3339Nano),
		EventType:    eventType,
		ActionSource: "security",
		Severity:     severity,
		UserRole:     userRole,
		Metadata:     metadata,
	}

	return GetAuditLogger().LogEvent(log)
}

// LogComplianceEvent is a helper function to log compliance-related events
func LogComplianceEvent(requestID string, complianceFlags map[string]bool, userRole string, metadata map[string]string) error {
	log := AuditLog{
		RequestID:       requestID,
		Timestamp:       time.Now().Format(time.RFC3339Nano),
		EventType:       "compliance_check",
		ActionSource:    "compliance",
		Severity:        SeverityInfo,
		UserRole:        userRole,
		ComplianceFlags: complianceFlags,
		Metadata:        metadata,
	}

	return GetAuditLogger().LogEvent(log)
}
