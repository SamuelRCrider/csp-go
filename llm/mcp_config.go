package llm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MCPServerConfig holds configuration for connecting to MCP servers
type MCPServerConfig struct {
	// Path to the MCP server executable or empty string for HTTP
	Path string

	// URL for HTTP transport (if Path is empty)
	URL string

	// Transport type: "stdio" or "http"
	Transport string

	// Additional connection options
	Options map[string]interface{}
}

// NewMCPServerConfig creates a new server configuration with defaults
func NewMCPServerConfig() *MCPServerConfig {
	return &MCPServerConfig{
		Transport: "stdio",
		Options:   make(map[string]interface{}),
	}
}

// DiscoverMCPServers tries to discover available MCP servers using various methods
func DiscoverMCPServers() ([]MCPServerConfig, error) {
	servers := []MCPServerConfig{}

	// 1. Check environment variables
	if serverPath := os.Getenv("MCP_SERVER_PATH"); serverPath != "" {
		servers = append(servers, MCPServerConfig{
			Path:      serverPath,
			Transport: "stdio",
		})
	}

	if serverURL := os.Getenv("MCP_SERVER_URL"); serverURL != "" {
		servers = append(servers, MCPServerConfig{
			URL:       serverURL,
			Transport: "http",
		})
	}

	// 2. Check common installation locations
	commonPaths := []string{
		"./mcp-server",
		filepath.Join(os.Getenv("HOME"), ".local/bin/mcp-server"),
		"/usr/local/bin/mcp-server",
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			// File exists
			servers = append(servers, MCPServerConfig{
				Path:      path,
				Transport: "stdio",
			})
		}
	}

	// 3. Parse MCP_SERVERS environment variable (comma-separated list)
	if serverList := os.Getenv("MCP_SERVERS"); serverList != "" {
		for _, server := range strings.Split(serverList, ",") {
			server = strings.TrimSpace(server)
			if strings.HasPrefix(server, "http://") || strings.HasPrefix(server, "https://") {
				servers = append(servers, MCPServerConfig{
					URL:       server,
					Transport: "http",
				})
			} else {
				servers = append(servers, MCPServerConfig{
					Path:      server,
					Transport: "stdio",
				})
			}
		}
	}

	// Return discovered servers or error if none found
	if len(servers) == 0 {
		return nil, fmt.Errorf("no MCP servers discovered; please set MCP_SERVER_PATH, MCP_SERVER_URL, or MCP_SERVERS environment variable")
	}

	return servers, nil
}

// GetMCPServerConfig returns an appropriate MCP server configuration
// It accepts an optional serverPath parameter that takes precedence if provided
func GetMCPServerConfig(serverPath string) (*MCPServerConfig, error) {
	// If direct path provided, use it
	if serverPath != "" {
		if strings.HasPrefix(serverPath, "http://") || strings.HasPrefix(serverPath, "https://") {
			return &MCPServerConfig{
				URL:       serverPath,
				Transport: "http",
			}, nil
		}
		return &MCPServerConfig{
			Path:      serverPath,
			Transport: "stdio",
		}, nil
	}

	// Try to discover available servers
	servers, err := DiscoverMCPServers()
	if err != nil {
		return nil, err
	}

	// Return the first available server
	return &servers[0], nil
}

// LoadMCPConfig loads and merges the MCP configuration from various sources
func LoadMCPConfig(config *MCPConfig) *MCPConfig {
	// Start with defaults if config is nil
	if config == nil {
		config = &MCPConfig{
			ToolName:     "csp.llm.wrap",
			Model:        "default",
			Temperature:  0.7,
			MaxTokens:    1024,
			Timeout:      30,
			RetryCount:   2,
			RetryBackoff: 500,
		}

		// Override defaults with environment variables if present
		if toolName := os.Getenv("MCP_TOOL_NAME"); toolName != "" {
			config.ToolName = toolName
		}

		if model := os.Getenv("MCP_MODEL"); model != "" {
			config.Model = model
		}

		// Add other environment-based configuration here
	}

	// For existing configs, we don't override with environment variables
	// as the explicitly provided values take precedence

	return config
}
