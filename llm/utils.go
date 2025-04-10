package llm

import (
	"encoding/json"
	"fmt"
	"time"
)

// generateRequestID creates a unique ID for request tracking
func generateRequestID() string {
	// Format: timestamp + random hex
	return fmt.Sprintf("%d-%x", time.Now().UnixNano(), time.Now().Nanosecond())
}

// estimateInputTokens provides a rough estimate of tokens in the input
func estimateInputTokens(input string) int {
	// Rough estimate: 1 token ≈ 4 characters for English text
	return len(input) / 4
}

// estimateOutputTokens provides a rough estimate of tokens in the output
func estimateOutputTokens(output string) int {
	// Rough estimate: 1 token ≈ 4 characters for English text
	return len(output) / 4
}

// estimateConversationTokens provides a rough estimate of tokens in a conversation
func estimateConversationTokens(conv *Conversation) int {
	total := 0

	// Add overhead for conversation format (4 tokens per message for the format itself)
	total += len(conv.Messages) * 4

	// Add tokens for each message content
	for _, msg := range conv.Messages {
		total += estimateInputTokens(msg.Content)
	}

	return total
}

// estimateInputTokensFromParts estimates tokens in content parts
func estimateInputTokensFromParts(parts []ContentPart) int {
	total := 0

	for _, part := range parts {
		if part.Type == "text" {
			total += estimateInputTokens(part.Text)
		} else if part.Type == "image" {
			// Image token estimation is model-dependent but typically uses a multiplier
			// This is a simplified estimation
			total += 100 // Placeholder for image token estimation
		}
	}

	return total
}

// jsonToMap converts JSON data to a map
func jsonToMap(data []byte) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := json.Unmarshal(data, &result)
	return result, err
}
