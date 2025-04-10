# MCP Integration Guide for CSP SDK

This guide explains how to integrate the Model Context Protocol (MCP) with the Context Security Pipeline (CSP) SDK.

## Overview

The Model Context Protocol (MCP) provides a standardized way for applications to interact with Large Language Models (LLMs). The CSP SDK integrates with MCP to:

1. Apply security policies to LLM interactions
2. Protect sensitive information
3. Enforce compliance rules
4. Provide comprehensive audit logging
5. Rate limit requests
6. Validate inputs and outputs

## Setting Up MCP

### Option 1: Global Configuration

Set the MCP server path once at the beginning of your application:

```go
import "samcrider/csp"

func init() {
    // Configure the MCP server globally
    csp.ConfigureMCP("/path/to/mcp-server")
}
```

### Option 2: Environment Variables

Configure MCP using environment variables:

```bash
# Set MCP server location
export MCP_SERVER_PATH=/path/to/mcp-server
# or for HTTP-based MCP servers
export MCP_SERVER_URL=https://mcp.example.com

# Configure MCP parameters
export MCP_TOOL_NAME=custom.llm.tool
export MCP_MODEL=gpt-4-turbo
export MCP_SERVERS=server1,server2,server3  # Comma-separated list for redundancy
```

### Option 3: Direct Configuration

Provide MCP configuration directly when calling the SDK:

```go
import (
    "samcrider/csp"
    "samcrider/csp/llm"
    "time"
)

func main() {
    mcpConfig := &llm.MCPConfig{
        ToolName:          "csp.llm.wrap",
        Model:             "claude-3-opus",
        Temperature:       0.2,
        MaxTokens:         2000,
        Timeout:           time.Second * 30,
        RetryCount:        2,
        RetryBackoff:      time.Second * 1, // Exponential backoff starts at this duration
        EnableDLP:         true,
        RateLimitEnabled:  true,
        RequestsPerMinute: 100,
        AuditLevel:        "standard",
        RequestValidation: ValidationConfig{
            Enabled:   true,
            MaxLength: 16384,  // 16KB
        },
        ResponseValidation: ValidationConfig{
            Enabled:   true,
            MaxLength: 65536,  // 64KB
        },
    }

    result, err := csp.RunCSPWithConfig(
        "Process this text...",
        "user",
        "/path/to/mcp-server",
        mcpConfig,
    )
}
```

## MCP Server Discovery

The SDK will attempt to discover MCP servers in the following order:

1. Explicit path provided in method calls
2. `MCP_SERVER_PATH` or `MCP_SERVER_URL` environment variables
3. `MCP_SERVERS` environment variable (comma-separated list)
4. Common installation locations:
   - `./mcp-server`
   - `~/.local/bin/mcp-server`
   - `/usr/local/bin/mcp-server`

## Advanced MCP Features

### Conversation Support

Process multi-turn conversations with security applied to each message:

```go
import (
    "samcrider/csp/llm"
)

func main() {
    // Create adapter
    adapter, _ := llm.NewCSPMCPAdapter(ctx, "./mcp-server", policy, config)

    // Create conversation
    conv := &llm.Conversation{
        Role: "user",
        Messages: []llm.Message{
            {
                Role:    "system",
                Content: "You are a helpful assistant.",
            },
            {
                Role:    "user",
                Content: "Hello, my email is test@example.com",
            },
        },
    }

    // Process next user message in conversation
    response, err := adapter.ProcessConversation(conv, "Can you tell me more about my email?")
}
```

### Streaming Support

Process streaming responses with security controls:

```go
import (
    "context"
    "fmt"
    "samcrider/csp/llm"
)

func main() {
    // Create adapter
    adapter, _ := llm.NewCSPMCPAdapter(ctx, "./mcp-server", policy, config)

    // Create a channel for receiving streamed chunks
    stream := make(chan string)
    errChan := make(chan error)

    // Start streaming in background
    go func() {
        err := adapter.ProcessStream("Generate a story", stream)
        if err != nil {
            errChan <- err
        }
        close(stream)
    }()

    // Process streamed chunks
    for {
        select {
        case chunk, ok := <-stream:
            if !ok {
                return // Stream closed
            }
            fmt.Print(chunk)
        case err := <-errChan:
            fmt.Printf("Error: %v\n", err)
            return
        }
    }
}
```

### Metadata Support

Include custom metadata with requests for tracking and analytics:

```go
func main() {
    adapter, _ := llm.NewCSPMCPAdapter(ctx, "./mcp-server", policy, config)

    // Include custom metadata
    metadata := map[string]interface{}{
        "department": "HR",
        "session_id": "sess_12345",
        "request_source": "mobile_app",
    }

    response, err := adapter.ProcessWithMetadata("Process this text...", metadata)
}
```

## Configuration Options

| Option             | Description                                             | Default        |
| ------------------ | ------------------------------------------------------- | -------------- |
| ToolName           | Name of the MCP tool to call                            | `csp.llm.wrap` |
| Model              | LLM model to use                                        | `default`      |
| Temperature        | Controls randomness (0.0-1.0)                           | 0.7            |
| MaxTokens          | Maximum tokens to generate                              | 1024           |
| Timeout            | Request timeout                                         | 30s            |
| RetryCount         | Number of retries on failure                            | 2              |
| RetryBackoff       | Initial backoff duration (will increase exponentially)  | 1s             |
| EnableDLP          | Enable Data Loss Prevention                             | true           |
| DLPPatterns        | Custom DLP patterns to add                              | []             |
| RateLimitEnabled   | Enable rate limiting                                    | false          |
| RequestsPerMinute  | Maximum requests per minute if rate limiting enabled    | 60             |
| AuditLevel         | Audit logging detail (`minimal`, `standard`, `verbose`) | `standard`     |
| MaxContentSize     | Maximum content size in bytes                           | 32768          |
| RequestValidation  | Validation settings for requests                        | Enabled        |
| ResponseValidation | Validation settings for responses                       | Enabled        |
| ExtraParams        | Additional parameters to pass to the MCP server         | nil            |

## Example Usage

```go
package main

import (
    "fmt"
    "samcrider/csp"
    "samcrider/csp/llm"
)

func main() {
    // Configure MCP server
    csp.ConfigureMCP("./mcp-server")

    // Set up custom MCP configuration
    mcpConfig := &llm.MCPConfig{
        Model:         "gpt-4",
        Temperature:   0.3,
        EnableDLP:     true,
        AuditLevel:    "standard",
    }

    // Process text with CSP
    input := "My name is John Smith and my email is john.smith@example.com"
    result, err := csp.RunCSPWithConfig(input, "user", "", mcpConfig)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    fmt.Printf("Result: %s\n", result)
}
```

## Error Handling

The CSP SDK categorizes MCP errors to help with proper handling:

```go
if err != nil {
    // Check for specific error types
    var cspErr llm.CSPError
    if errors.As(err, &cspErr) {
        switch cspErr.Category() {
        case llm.ErrorCategoryTimeout:
            // Handle timeout
        case llm.ErrorCategoryRateLimit:
            // Handle rate limiting
        case llm.ErrorCategoryDLP:
            // Handle DLP violation
        case llm.ErrorCategoryValidation:
            // Handle validation error
        case llm.ErrorCategoryModel:
            // Handle model-specific error
        default:
            // Handle other errors
        }
    }
}
```

## Building Custom MCP Servers

For examples of how to build custom MCP servers, see the `examples/sample_mcp_server.go` in this repository. For more information about the Model Context Protocol, visit [modelcontextprotocol.io](https://modelcontextprotocol.io/).

## Troubleshooting

If you encounter issues with MCP integration:

1. Ensure the MCP server is running and accessible
2. Check environment variables are correctly set
3. Try explicit server path in `RunCSPWithConfig`
4. Set `AuditLevel` to "verbose" for detailed logging
5. Check for rate limiting errors if experiencing intermittent failures
6. Look for error messages about MCP server discovery

For more help, consult the main CSP SDK documentation.
