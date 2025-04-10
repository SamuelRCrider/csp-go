package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Minimal implementation of an MCP server that responds to tool calls
func main2() {
	server()
}

func server() {
	fmt.Fprintf(os.Stderr, "Sample MCP Server starting...\n")

	// Process each request as it comes in
	processStdioRequests()
}

func processStdioRequests() {
	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for {
		// Read request
		var request map[string]interface{}
		err := decoder.Decode(&request)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding request: %v\n", err)
			continue
		}

		// Process request
		response := handleRequest(request)

		// Send response
		if err := encoder.Encode(response); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding response: %v\n", err)
			continue
		}
	}
}

func handleRequest(request map[string]interface{}) map[string]interface{} {
	// Log request details
	fmt.Fprintf(os.Stderr, "Received request: %v\n", request)

	// Extract method and params
	method, _ := request["method"].(string)

	// Create base response
	response := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      request["id"],
	}

	// Handle method
	switch method {
	case "call_tool":
		// Get tool parameters
		paramsObj, _ := request["params"].(map[string]interface{})
		toolName, _ := paramsObj["name"].(string)
		toolArgs, _ := paramsObj["arguments"].(map[string]interface{})

		// Process tool call
		toolResponse := processToolCall(toolName, toolArgs)
		response["result"] = toolResponse

	default:
		response["error"] = map[string]interface{}{
			"code":    -32601,
			"message": "Method not found",
		}
	}

	return response
}

func processToolCall(toolName string, args map[string]interface{}) map[string]interface{} {
	fmt.Fprintf(os.Stderr, "Processing tool call: %s with args: %v\n", toolName, args)

	// Extract relevant info
	var input string
	var model string

	// Try to get input from different possible argument formats
	if inputVal, ok := args["input"]; ok {
		input, _ = inputVal.(string)
	} else if messagesVal, ok := args["messages"]; ok {
		// Handle messages format
		if messages, ok := messagesVal.([]interface{}); ok && len(messages) > 0 {
			lastMsg := messages[len(messages)-1]
			if msgObj, ok := lastMsg.(map[string]interface{}); ok {
				if content, ok := msgObj["content"].(string); ok {
					input = content
				}
			}
		}
	}

	if modelVal, ok := args["model"]; ok {
		model, _ = modelVal.(string)
	}

	// Create a simple response by processing the input
	responseText := generateResponse(input, model)

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": responseText,
			},
		},
		"is_error": false,
	}
}

func generateResponse(input string, model string) string {
	// Process the input - this is where you would call an actual LLM
	// For this example, we just create a simple echo response
	var responseText string

	if strings.Contains(strings.ToLower(input), "hello") {
		responseText = "Hello! How can I help you today?"
	} else if strings.Contains(strings.ToLower(input), "weather") {
		responseText = "I'm sorry, I don't have access to current weather information."
	} else if strings.Contains(strings.ToLower(input), "name") {
		responseText = "I'm a sample MCP server for testing the CSP SDK."
	} else {
		responseText = fmt.Sprintf("You said: %s\nI processed this with model: %s", input, model)
	}

	return responseText
}
