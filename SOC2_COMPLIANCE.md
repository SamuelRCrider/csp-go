# SOC 2 Compliance in CSP-Go

This document outlines how the CSP-Go library implements SOC 2 compliance principles for secure LLM interactions.

## Overview

The Context Security Protocol (CSP-Go) is designed to provide a secure framework for LLM interactions that meets SOC 2 compliance requirements. Organizations leveraging this SDK can ensure their LLM interactions adhere to security, availability, processing integrity, confidentiality, and privacy standards.

## Key Security Features

### 1. Advanced Data Loss Prevention (DLP)

- **Risk-Based Detection**: Multi-level risk categorization (Low, Medium, High, Critical)
- **Compliance Categorization**: Automatic classification of sensitive data (PII, Financial, Health, GDPR, Credentials)
- **Pattern-Based Detection**: Comprehensive regex patterns for detecting sensitive information
- **Data Fingerprinting**: Create hashes of sensitive data to track it across conversations
- **Pre-Request & Post-Response Scanning**: Complete coverage of both input and output content
- **Multiple Protection Methods**:
  - Content redaction with type labels
  - Content masking that preserves context
  - AES-256 encryption
  - Deterministic tokenization

### 2. Authentication & Authorization

- **Request ID Tracking**: Each request receives a unique ID for comprehensive audit trails
- **User Role-Based Policies**: Security policies applied differently based on user role
- **Error Categorization**: Standardized error types for security-related issues
- **Policy Condition Matching**: Check conditions like user roles before applying security rules

### 3. Rate Limiting & DoS Protection

- **Configurable Rate Limits**: Set requests per minute by user/role
- **Exponential Backoff**: Intelligent retry with increasing delays
- **Detailed Rate Information**: Provides current count, limit, and reset time
- **Custom Identifiers**: Use role, user ID, or custom identifiers for rate limiting

### 4. Input/Output Validation

- **Content Size Limits**: Configurable maximum input and output sizes
- **Request Validation**: Validate incoming requests before processing
- **Response Validation**: Ensure responses meet security and format requirements
- **Content Type Restrictions**: Options to restrict URLs, code blocks, or other content types

### 5. Enterprise-Grade Audit Logging

- **Multi-Level Logging**: Configurable verbosity (minimal, standard, verbose)
- **Structured JSON Logging**: All events logged in consistent JSON format
- **Request/Response Correlation**: All logs include request IDs for traceability
- **Performance Metrics**: Duration and token usage metrics for each request
- **Transformation Tracking**: Record all transformations applied to content

### 6. Comprehensive Error Handling

- **Categorized Errors**: Standardized error categories (Authentication, Authorization, Validation, etc.)
- **Error Metadata**: Additional context information in error objects
- **Context-Aware Errors**: Errors include request IDs and timestamps for correlation
- **Client-Safe Messages**: User-facing errors are informative but don't leak system details

### 7. Secure MCP Integration

- **Transport Security**: Support for secure MCP communication
- **Server Validation**: MCP server discovery and validation
- **Timeout Controls**: Prevent hanging connections with configurable timeouts
- **Retry Mechanisms**: Resilient interaction with MCP servers

## Configuration Options

All security features can be configured via the `MCPConfig` structure, including:

```go
MCPConfig {
    // Basic LLM configuration
    ToolName            string        // MCP tool name
    Model               string        // Model to use
    Temperature         float64       // Randomness control
    MaxTokens           int           // Maximum tokens per response

    // Security features
    EnableDLP           bool          // Enable/disable DLP scanning
    DLPPatterns         []string      // Custom patterns for sensitive data
    RateLimitEnabled    bool          // Enable/disable rate limiting
    RequestsPerMinute   int           // Rate limit threshold
    AuditLevel          string        // Audit verbosity (minimal, standard, verbose)
    MaxContentSize      int           // Maximum content size in bytes

    // Request/response validation
    RequestValidation: ValidationConfig{
        Enabled:   bool,              // Enable input validation
        MaxLength: int,               // Maximum input length
    },
    ResponseValidation: ValidationConfig{
        Enabled:   bool,              // Enable output validation
        MaxLength: int,               // Maximum output length
    },

    // Retry and resilience
    Timeout             time.Duration // Request timeout
    RetryCount          int           // Number of retries
    RetryBackoff        time.Duration // Initial backoff duration
}
```

## Risk Assessment Framework

The DLP scanner assesses risk using a structured framework:

1. **Risk Levels**:

   - **Low (1)**: Minimal sensitivity (e.g., ZIP codes)
   - **Medium (2)**: Moderate sensitivity (e.g., email addresses)
   - **High (3)**: Sensitive PII (e.g., SSNs, credit cards)
   - **Critical (4)**: Highly sensitive (e.g., API keys, passwords)

2. **Compliance Categories**:

   - **PII**: General personally identifiable information
   - **Financial**: Payment card data, account numbers
   - **Health**: PHI and HIPAA-relevant information
   - **GDPR**: EU-specific protected information
   - **Credential**: Passwords, API keys, tokens
   - **Source Code**: Intellectual property, code snippets

3. **Risk Assessment Output**:
   ```go
   type RiskAssessment struct {
       HighestRisk           RiskLevel
       HighestRiskCategory   ComplianceCategory
       TotalMatches          int
       CategoryBreakdown     map[ComplianceCategory]int
   }
   ```

## Audit Trail

The system maintains comprehensive audit logs including:

1. **Pre-Request Processing**:

   - Request validation
   - DLP scanning results (type, risk level, compliance category)
   - Content transformations (redaction, encryption, etc.)
   - Rate limit checks

2. **Request Processing**:

   - Request timing
   - Retry attempts and backoff durations
   - Error conditions with categorization

3. **Response Processing**:
   - Response validation
   - Response sanitization
   - Token usage and performance metrics

Example audit log:

```json
{
  "timestamp": "2023-05-15T14:22:33Z",
  "request_id": "csp_req_7f8e9d2c",
  "user_role": "support",
  "input_chars": 235,
  "sensitive_matches": 2,
  "dlp_passed": true,
  "validation_passed": true,
  "rate_limit_count": 42,
  "transformed": "My email is [REDACTED:email]",
  "duration_ms": 378,
  "matches": [
    {
      "start_index": 12,
      "end_index": 32,
      "value": "jane.doe@example.com",
      "type": "email",
      "action": "redact",
      "risk_level": "medium",
      "compliance_type": "pii"
    }
  ],
  "action_source": "pre-request"
}
```

## Compliance with SOC 2 Principles

### Security

- Risk-based DLP with multiple protection methods
- Input/output validation with size limits
- Comprehensive error handling with categorization
- Role-based policy application

### Availability

- Rate limiting to prevent DoS
- Retry mechanisms with exponential backoff
- Timeout management to prevent resource exhaustion
- Server discovery with fallbacks

### Processing Integrity

- Request validation before processing
- Response validation after processing
- Comprehensive transformation logging
- Request/response correlation with IDs

### Confidentiality

- Multi-level DLP scanning
- Content redaction, masking, encryption
- Risk-based assessment of sensitive data
- Data fingerprinting for persistent protection

### Privacy

- PII detection with compliance categorization
- Role-based content policies
- Minimization of data exposure
- Audit trails of all data transformations

## Implementation Example

```go
import (
    "context"
    "fmt"
    "samcrider/csp/core"
    "samcrider/csp/llm"
    "time"
)

func main() {
    // Load policy
    policy, _ := core.LoadPolicy("config/policy.yaml")

    // Create context with role
    ctx := &core.Context{Role: "admin"}

    // Configure SOC 2 compliant settings
    config := &llm.MCPConfig{
        // Basic LLM configuration
        Model:         "gpt-4",
        Temperature:   0.3,
        MaxTokens:     2000,

        // SOC 2 security features
        EnableDLP:         true,
        RateLimitEnabled:  true,
        RequestsPerMinute: 100,
        AuditLevel:        "standard",
        MaxContentSize:    32768,  // 32KB

        // Request/response validation
        RequestValidation: llm.ValidationConfig{
            Enabled:   true,
            MaxLength: 16384,  // 16KB
        },
        ResponseValidation: llm.ValidationConfig{
            Enabled:   true,
            MaxLength: 65536,  // 64KB
        },

        // Retry and resilience
        Timeout:      time.Second * 30,
        RetryCount:   2,
        RetryBackoff: time.Second * 1,
    }

    // Create adapter with security features
    adapter, _ := llm.NewCSPMCPAdapter(ctx, "./path-to-server", policy, config)

    // Process with full SOC 2 compliance
    result, err := adapter.Process("Process this sensitive input...")
    if err != nil {
        // Handle errors with proper categorization
        var cspErr llm.CSPError
        if errors.As(err, &cspErr) {
            switch cspErr.Category() {
            case llm.ErrorCategoryDLP:
                fmt.Println("Security violation: detected sensitive data")
            case llm.ErrorCategoryRateLimit:
                fmt.Println("Rate limit exceeded")
            // Handle other error categories
            }
        }
    }
}
```

## Best Practices

1. **Enable Risk-Based DLP** in production environments
2. **Set appropriate rate limits** based on expected usage patterns
3. **Use the highest audit level** (verbose) in security-sensitive scenarios
4. **Customize the default policy** for your specific industry and compliance needs
5. **Regularly review audit logs** to ensure compliance and detect issues
6. **Update DLP patterns** as new sensitive data types are identified
7. **Add fingerprinting** for high-value data specific to your organization
8. **Configure timeouts and retries** appropriately for your environment
9. **Set validation limits** based on your application's requirements
10. **Use role-based policies** to implement least-privilege principles
