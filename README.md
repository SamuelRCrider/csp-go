# Context Security Protocol (CSP)

A comprehensive Go SDK for securing LLM interactions in enterprise environments.

## Overview

The Context Security Protocol (CSP) is an SDK that provides a security wrapper around Large Language Model interactions, helping organizations leverage AI capabilities while maintaining compliance with privacy regulations and security best practices. CSP acts as a middleware layer that sanitizes inputs before they reach an LLM and filters outputs to prevent sensitive information leakage.

CSP is designed for enterprise use cases where regulatory compliance (HIPAA, GDPR, SOC 2, etc.) and data protection are critical concerns, particularly in industries like healthcare, finance, legal, and government.

## Key Features

- **Multi-Layered Protection**:

  - **Advanced DLP Scanning**: Enhanced pattern detection with risk categorization (Low, Medium, High, Critical)
  - **Content Classification**: Automatic categorization by compliance type (PII, Financial, Health, GDPR, Credentials)
  - **Multiple Protection Actions**: Redaction, masking, AES-256 encryption, and deterministic tokenization
  - **Data Fingerprinting**: Track and protect high-value data across multiple interactions
  - **Context-Aware Processing**: Customize security policies based on user roles and context

- **MCP Integration**:

  - **Full MCP Support**: Seamless integration with the Model Context Protocol
  - **Multi-Provider Compatibility**: Works with any LLM that supports the MCP standard
  - **Conversation History Support**: Maintain security across multi-turn conversations
  - **Streaming Support**: Process streaming LLM responses safely
  - **Auto-Discovery**: Automatically locate MCP servers in the environment

- **Enterprise-Grade Security**:
  - **Rate Limiting**: Configurable request limits with exponential backoff
  - **SOC 2 Compliance**: Comprehensive controls for security, availability, and confidentiality
  - **Rich Audit Logging**: Detailed, structured logging with request correlation
  - **Error Categorization**: Standardized error types for security-related issues
  - **Request Validation**: Input/output validation with size limits and content restrictions

## Installation

```bash
# Install the CSP SDK using go get
go get github.com/SamuelRCrider/csp-go

# Set mandatory encryption key (32 bytes for AES-256) in your environment
export CSP_ENCRYPTION_KEY="your-32-byte-key-here-for-aes-security"
```

## Quick Start

### CLI Testing - outdated

The included CLI tool provides a quick way to test CSP functionality:

```bash
# Clone the repository to access the CLI tool
git clone https://github.com/SamuelRCrider/csp-go
cd csp-go

# Run the basic CLI demo
go run cmd/main.go
```

### Basic Usage

Simplest way to use CSP in your application:

```go
package main

import (
	"fmt"
	"github.com/SamuelRCrider/csp-go"
)

func main() {
	// Process text through CSP with default settings
	// This will auto-discover the MCP server
	output, err := csp.RunCSP("Process this sensitive text containing jane.doe@example.com", "admin")
	if err != nil {
		panic(err)
	}

	fmt.Println("Secure output:", output)
}
```

### Advanced Configuration

Use CSP with custom settings:

```go
package main

import (
	"fmt"
	"time"
	"github.com/SamuelRCrider/csp-go"
	"github.com/SamuelRCrider/csp-go/llm"
)

func main() {
	// Configure global MCP server (optional)
	// This sets the MCP_SERVER_PATH environment variable for later use
	csp.ConfigureMCPServer("/path/to/mcp-server")

	// Configure MCP with advanced options
	mcpConfig := &llm.MCPConfig{
		ToolName:          "csp.llm.wrap",
		Model:             "gpt-4-turbo",
		Temperature:       0.2,
		MaxTokens:         2000,
		Timeout:           time.Second * 30,
		RetryCount:        2,
		EnableDLP:         true,
		RateLimitEnabled:  true,
		RequestsPerMinute: 100,
		AuditLevel:        "standard",
	}

	result, err := csp.RunCSPWithConfig(
		"Process this sensitive text...",
		"admin",
		"/path/to/mcp-server", // Can also be "" to use globally configured server or auto-discovery
		mcpConfig,
	)

	if err != nil {
		panic(err)
	}

	fmt.Println("Secure output:", result)
}
```

### Direct Policy Usage

For applications that need to apply security policies without LLM integration:

```go
package main

import (
	"fmt"
	"github.com/SamuelRCrider/csp-go/core"
)

func main() {
	// Load policy from file
	policy, err := core.LoadPolicy("config/default_policy.yaml")
	if err != nil {
		panic(err)
	}

	// Or create a policy programmatically
	builder := core.NewPolicyBuilder()
	customPolicy := builder.
		WithMetadata("1.0.0", "Custom Policy", "My App").
		AddRule("ssn", "ssn", "regex", `\d{3}-\d{2}-\d{4}`, core.ActionRedact).
		AddRule("credit_card", "credit_card", "regex", `\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`, core.ActionMask).
		Build()

	// Sample input with sensitive data
	input := "My SSN is 123-45-6789 and my credit card is 4111-1111-1111-1111"

	// Apply security policy
	matches := core.ScanText(input, customPolicy)
	secured := core.ApplyRedactions(input, matches)

	fmt.Println("Original:", input)
	fmt.Println("Secured:", secured)
}
```

## Policy Configuration

CSP uses YAML-based policy files to define security rules:

```yaml
rules:
  - match: "email"
    type: "regex"
    pattern: "[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+"
    action: "redact"
    conditions:
      roles: ["support", "guest"]

  - match: "ssn"
    type: "regex"
    pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
    action: "encrypt"

  - match: "project_zeus"
    type: "string"
    values: ["Zeus", "Project Zeus", "ZEUS"]
    action: "tokenize"
```

Each rule can specify:

- **match**: Identifier for the sensitive data type
- **type**: "regex" for pattern matching or "string" for exact matches
- **pattern**: Regular expression (for regex type)
- **values**: List of exact strings to match (for string type)
- **action**: How to handle matches ("redact", "mask", "encrypt", "tokenize")
- **conditions**: Optional restrictions on when to apply the rule (e.g., by user role)

## Security Actions

CSP supports multiple ways to handle sensitive data:

- **Redaction**: `My SSN is 123-45-6789` → `My SSN is [REDACTED:ssn]`
- **Masking**: `My SSN is 123-45-6789` → `My SSN is XXX-XX-6789`
- **Encryption**: `My SSN is 123-45-6789` → `My SSN is [ENCRYPTED:abcd1234...]`
- **Tokenization**: `Project Zeus` → `Project @@token_a1b2@@` (with reversible mapping)
- **Fingerprinting**: Track data by content hash for consistent handling across interactions

## Audit Logging

CSP generates detailed audit logs for all operations in JSON format:

```json
{
  "timestamp": "2023-05-15T14:22:33Z",
  "request_id": "csp_req_7f8e9d2c",
  "user_role": "support",
  "input": "My email is jane.doe@example.com",
  "transformed": "My email is [REDACTED:email]",
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

## Architecture

CSP follows a modular design with the following components:

```
┌───────────────────────────────────────────────────┐
│                       CSP                         │
├───────────────────────────────────────────────────┤
│ ┌─────────────┐    ┌─────────────┐ ┌────────────┐ │
│ │ Input       │    │ Risk        │ │ Output     │ │
│ │ Processing  │    │ Assessment  │ │ Filtering  │ │
│ └─────────────┘    └─────────────┘ └────────────┘ │
│                                                   │
│ ┌─────────────┐    ┌─────────────┐ ┌────────────┐ │
│ │ Redaction/  │    │ Rate        │ │ Audit      │ │
│ │ Encryption  │    │ Limiting    │ │ Logging    │ │
│ └─────────────┘    └─────────────┘ └────────────┘ │
├───────────────────────────────────────────────────┤
│               MCP Integration                     │
└───────────────────────────────────────────────────┘
                     │         ▲
                     ▼         │
┌───────────────────────────────────────────────────┐
│               LLM Provider APIs                   │
│      (OpenAI, Anthropic, Gemini, Azure, etc.)     │
└───────────────────────────────────────────────────┘
```

## Further Documentation

- [MCP Integration Guide](MCP_INTEGRATION.md): Details on integrating with MCP
- [SOC 2 Compliance](SOC2_COMPLIANCE.md): How CSP helps maintain SOC 2 compliance

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
