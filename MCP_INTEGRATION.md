# MCP Integration Guide for CSP SDK

This guide explains how to integrate the Model Context Protocol (MCP) with the Context Security Pipeline (CSP) SDK.

## Overview

The Model Context Protocol (MCP) provides a standardized way for applications to provide context to Large Language Models (LLMs). The CSP SDK integrates with MCP to:

1. Apply security policies to LLM interactions
2. Redact sensitive information
3. Enforce compliance rules
4. Provide audit logging

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
        ToolName:     "custom.llm.wrapper",
        Model:        "claude-3-opus",
        Temperature:  0.2,
        MaxTokens:    2000,
        Timeout:      time.Second * 30,
        RetryCount:   2,
        EnableDLP:    true,
        AuditLevel:   "standard",
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

## Configuration Options

| Option      | Description                                             | Default        |
| ----------- | ------------------------------------------------------- | -------------- |
| ToolName    | Name of the MCP tool to call                            | `csp.llm.wrap` |
| Model       | LLM model to use                                        | `default`      |
| Temperature | Controls randomness (0.0-1.0)                           | 0.7            |
| MaxTokens   | Maximum tokens to generate                              | 1024           |
| Timeout     | Request timeout                                         | 30s            |
| RetryCount  | Number of retries on failure                            | 2              |
| EnableDLP   | Enable Data Loss Prevention                             | true           |
| AuditLevel  | Audit logging detail (`minimal`, `standard`, `verbose`) | `standard`     |

## Example Usage

```go
package main

import (
    "fmt"
    "samcrider/csp"
)

func main() {
    // Configure MCP server
    csp.ConfigureMCP("./mcp-server")

    // Process text with CSP
    input := "My name is John Smith and my email is john.smith@example.com"
    result, err := csp.RunCSP(input, "user")
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    fmt.Printf("Result: %s\n", result)
}
```

## Building Custom MCP Servers

For examples of how to build custom MCP servers, see the `examples/sample_mcp_server.go` in this repository. For more information about the Model Context Protocol, visit [modelcontextprotocol.io](https://modelcontextprotocol.io/).

## Troubleshooting

If you encounter issues with MCP integration:

1. Ensure the MCP server is running and accessible
2. Check environment variables are correctly set
3. Try explicit server path in `RunCSPWithConfig`
4. Look for error messages about MCP server discovery

For more help, consult the main CSP SDK documentation.
