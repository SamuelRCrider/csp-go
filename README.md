# Context Security Protocol (CSP)

A comprehensive Go SDK for securing LLM interactions in enterprise environments.

## Overview

The Context Security Protocol (CSP) is an SDK that provides a security wrapper around Large Language Model interactions, helping organizations leverage AI capabilities while maintaining compliance with privacy regulations and security best practices. CSP acts as a middleware layer that sanitizes inputs before they reach an LLM and filters outputs to prevent sensitive information leakage.

CSP is designed for enterprise use cases where regulatory compliance (HIPAA, GDPR, SOC 2, etc.) and data protection are critical concerns, particularly in industries like healthcare, finance, legal, and government.

## Key Features

- **Multi-Layered Protection**:

  - **DLP Pattern Scanning**: Built-in detection for emails, SSNs, credit cards, phone numbers, and more
  - **Content Redaction**: Replace sensitive information with [REDACTED] placeholders
  - **Content Masking**: Partially mask information while preserving some context
  - **AES-256 Encryption**: Secure sensitive fields with strong encryption
  - **Deterministic Tokenization**: Replace values with consistent tokens that can be restored later

- **Contextual Security Control**:

  - **Role-Based Rules**: Apply different security policies based on user roles
  - **Conditional Processing**: Customize data handling based on specific contexts
  - **Pre-processing**: Sanitize inputs before they reach the LLM
  - **Post-processing**: Filter LLM outputs to catch leaked or hallucinated sensitive data

- **Enterprise-Grade Tools**:
  - **Comprehensive Audit Logging**: JSON-structured logs for compliance and monitoring
  - **YAML Policy Configuration**: Flexible, human-readable security rules
  - **LLM Provider Agnostic**: Works with any LLM through MCP integration
- **Compliance Support**:
  - **HIPAA**: Protect PHI through redaction and encryption
  - **GDPR**: Support data minimization and purpose limitation principles
  - **SOC 2**: Provide access controls and audit trails for security
  - **PCI DSS**: Shield payment card information from exposure

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/csp-go
cd csp-go

# Install dependencies
go mod tidy

# Set mandatory encryption key (32 bytes for AES-256)
export CSP_ENCRYPTION_KEY="your-32-byte-key-here-for-aes-security"
```

## Quick Start

### CLI Testing

The included CLI tool provides a quick way to test CSP functionality:

```bash
go run cmd/main.go
```

### SDK Integration

Use CSP in your Go applications:

```go
import (
	"context"
	"fmt"
	"samcrider/csp"
)

func main() {
	// Initialize CSP with options
	options := csp.Options{
		PolicyPath:    "config/default_policy.yaml",
		EncryptionKey: []byte(os.Getenv("CSP_ENCRYPTION_KEY")),
		AuditEnabled:  true,
	}

	cspHandler, err := csp.New(options)
	if err != nil {
		panic(err)
	}

	// Process text through CSP (for direct content security)
	result, err := cspHandler.ScanContent(context.Background(),
		"My email is jane.doe@example.com and SSN is 123-45-6789")
	if err != nil {
		panic(err)
	}

	fmt.Println("Scan results:", result)

	// For LLM interactions, use the simpler RunCSP wrapper
	output, err := csp.RunCSP("Tell me about jane.doe@example.com", "admin")
	if err != nil {
		panic(err)
	}

	fmt.Println("Secure LLM response:", output)
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
- **Masking**: `My SSN is 123-45-6789` → `My SSN is [MASKED:ssn]`
- **Encryption**: `My SSN is 123-45-6789` → `My SSN is [ENCRYPTED:abcd1234...]`
- **Tokenization**: `Project Zeus` → `Project @@token_a1b2@@` (with reversible mapping)

## Audit Logging

CSP generates detailed audit logs for all operations in JSON format:

```json
{
  "timestamp": "2023-05-15T14:22:33Z",
  "user_role": "support",
  "input": "My email is jane.doe@example.com",
  "transformed": "My email is [REDACTED:email]",
  "matches": [
    {
      "start_index": 12,
      "end_index": 32,
      "value": "jane.doe@example.com",
      "type": "email",
      "action": "redact"
    }
  ],
  "action_source": "pre-request"
}
```

These logs help demonstrate compliance with security requirements and provide a record of all data transformations.

## Architecture

CSP follows a modular design with the following components:

```
┌─────────────────────────────┐
│             CSP             │
├─────────────────────────────┤
│ ┌─────────┐    ┌─────────┐  │
│ │  Input  │    │ Output  │  │
│ │ Scanner │    │ Filter  │  │
│ └─────────┘    └─────────┘  │
│ ┌─────────┐    ┌─────────┐  │
│ │ Redactor│    │ Audit   │  │
│ │Encryptor│    │ Logger  │  │
│ └─────────┘    └─────────┘  │
├─────────────────────────────┤
│         MCP Adapter         │
└─────────────────────────────┘
          │         ▲
          ▼         │
┌─────────────────────────────┐
│      LLM Provider API       │
│  (OpenAI, Anthropic, etc.)  │
└─────────────────────────────┘
```

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
# csp_go
