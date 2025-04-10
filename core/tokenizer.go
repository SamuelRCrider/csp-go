package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// TokenFormat defines how tokens are formatted
type TokenFormat string

const (
	// FormatPrefix uses a prefix and suffix to identify tokens
	FormatPrefix TokenFormat = "prefix"

	// FormatFull completely replaces the value with the token
	FormatFull TokenFormat = "full"

	// FormatPreserving preserves format of the original value (e.g., for credit cards)
	FormatPreserving TokenFormat = "preserving"
)

// TokenizedValue represents a tokenized value with metadata
type TokenizedValue struct {
	// The actual token
	Token string `json:"token"`

	// When the token was created
	CreatedAt time.Time `json:"created_at"`

	// When the token expires (zero time means no expiration)
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Original value, stored encrypted if EnableEncryption is true
	Original string `json:"original,omitempty"`

	// Whether the original value is encrypted
	IsEncrypted bool `json:"is_encrypted,omitempty"`

	// Type of data that was tokenized
	DataType string `json:"data_type,omitempty"`

	// Format of the token
	Format TokenFormat `json:"format"`

	// Hash of the original value for verification
	OriginalHash string `json:"original_hash"`

	// User/request ID that created this token
	CreatedBy string `json:"created_by,omitempty"`
}

// TokenizerConfig defines configuration for the tokenizer
type TokenizerConfig struct {
	// Format to use for tokens
	Format TokenFormat

	// Prefix to use for tokens (if using FormatPrefix)
	Prefix string

	// Suffix to use for tokens (if using FormatPrefix)
	Suffix string

	// Whether to encrypt the original values
	EnableEncryption bool

	// Whether to persist the token vault to disk
	EnablePersistence bool

	// Path to persist the token vault
	PersistencePath string

	// How long tokens are valid for (zero means no expiration)
	TokenTTL time.Duration

	// How often to check for expired tokens
	ExpirationCheckInterval time.Duration

	// Whether to enable token revocation
	EnableRevocation bool
}

// Tokenizer provides SOC 2 compliant tokenization services
type Tokenizer struct {
	config TokenizerConfig

	// Map from token to tokenized value
	vault map[string]TokenizedValue

	// Map from original value hash to token for lookups
	reverseIndex map[string]string

	// Lock for concurrent access
	lock sync.RWMutex

	// Channel to signal shutdown of background tasks
	stopCh chan struct{}

	// Whether the tokenizer has been initialized
	initialized bool
}

// DefaultTokenizer is the singleton tokenizer instance
var DefaultTokenizer *Tokenizer
var tokenizerOnce sync.Once

// GetTokenizer returns the singleton tokenizer instance
func GetTokenizer() *Tokenizer {
	tokenizerOnce.Do(func() {
		// Default configuration
		config := TokenizerConfig{
			Format:                  FormatPrefix,
			Prefix:                  "@@token_",
			Suffix:                  "@@",
			EnableEncryption:        true,
			EnablePersistence:       true,
			PersistencePath:         "tokens.json",
			TokenTTL:                30 * 24 * time.Hour, // 30 days
			ExpirationCheckInterval: 1 * time.Hour,
			EnableRevocation:        true,
		}

		DefaultTokenizer = NewTokenizer(config)
		DefaultTokenizer.Initialize()
	})

	return DefaultTokenizer
}

// NewTokenizer creates a new tokenizer with the given configuration
func NewTokenizer(config TokenizerConfig) *Tokenizer {
	return &Tokenizer{
		config:       config,
		vault:        make(map[string]TokenizedValue),
		reverseIndex: make(map[string]string),
		stopCh:       make(chan struct{}),
	}
}

// Initialize sets up the tokenizer
func (t *Tokenizer) Initialize() error {
	// Don't initialize multiple times
	if t.initialized {
		return nil
	}

	// Load from disk if persistence is enabled
	if t.config.EnablePersistence {
		if err := t.loadFromDisk(); err != nil {
			// Log but continue - not a fatal error
			LogSecurityEvent("system", "tokenizer_load_failed", SeverityWarning, "system", map[string]string{
				"error": err.Error(),
			})
		}
	}

	// Start background tasks
	if t.config.TokenTTL > 0 {
		go t.expirationChecker()
	}

	t.initialized = true
	return nil
}

// Shutdown gracefully shuts down the tokenizer
func (t *Tokenizer) Shutdown() error {
	// Signal background tasks to stop
	close(t.stopCh)

	// Persist tokens to disk if enabled
	if t.config.EnablePersistence {
		return t.persistToDisk()
	}

	return nil
}

// loadFromDisk loads the token vault from disk
func (t *Tokenizer) loadFromDisk() error {
	t.lock.Lock()
	defer t.lock.Unlock()

	// Check if file exists
	if _, err := os.Stat(t.config.PersistencePath); os.IsNotExist(err) {
		// File doesn't exist yet, that's OK
		return nil
	}

	// Read file
	data, err := ioutil.ReadFile(t.config.PersistencePath)
	if err != nil {
		return fmt.Errorf("failed to read token vault: %w", err)
	}

	// Parse JSON
	var tokens []TokenizedValue
	if err := json.Unmarshal(data, &tokens); err != nil {
		return fmt.Errorf("failed to parse token vault: %w", err)
	}

	// Add tokens to vault
	for _, tv := range tokens {
		// Skip expired tokens
		if !tv.ExpiresAt.IsZero() && tv.ExpiresAt.Before(time.Now()) {
			continue
		}

		// Add to vault
		t.vault[tv.Token] = tv

		// Add to reverse index if original is stored (encrypted or not)
		if tv.Original != "" || tv.OriginalHash != "" {
			t.reverseIndex[tv.OriginalHash] = tv.Token
		}
	}

	return nil
}

// persistToDisk saves the token vault to disk
func (t *Tokenizer) persistToDisk() error {
	t.lock.RLock()
	defer t.lock.RUnlock()

	// Convert vault to slice
	tokens := make([]TokenizedValue, 0, len(t.vault))
	for _, tv := range t.vault {
		tokens = append(tokens, tv)
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize token vault: %w", err)
	}

	// Create directory if needed
	dir := filepath.Dir(t.config.PersistencePath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory for token vault: %w", err)
		}
	}

	// Write to file
	if err := ioutil.WriteFile(t.config.PersistencePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write token vault: %w", err)
	}

	return nil
}

// expirationChecker periodically checks for and removes expired tokens
func (t *Tokenizer) expirationChecker() {
	ticker := time.NewTicker(t.config.ExpirationCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.removeExpiredTokens()
		case <-t.stopCh:
			return
		}
	}
}

// removeExpiredTokens removes expired tokens from the vault
func (t *Tokenizer) removeExpiredTokens() {
	t.lock.Lock()
	defer t.lock.Unlock()

	now := time.Now()
	expiredCount := 0

	// Find expired tokens
	for token, tv := range t.vault {
		if !tv.ExpiresAt.IsZero() && tv.ExpiresAt.Before(now) {
			// Remove from vault and reverse index
			delete(t.vault, token)
			delete(t.reverseIndex, tv.OriginalHash)
			expiredCount++
		}
	}

	if expiredCount > 0 {
		// Log expired tokens
		LogSecurityEvent("system", "tokens_expired", SeverityInfo, "system", map[string]string{
			"count": fmt.Sprintf("%d", expiredCount),
		})

		// Persist changes
		if t.config.EnablePersistence {
			t.persistToDisk()
		}
	}
}

// hashValue creates a hash of a value for storage and lookup
func hashValue(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

// TokenizeValue returns a deterministic token for a given value with SOC 2 compliance
func (t *Tokenizer) TokenizeValue(value, dataType, requestID string) string {
	if value == "" {
		return ""
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	// Check if value is already tokenized
	valueHash := hashValue(value)
	if token, exists := t.reverseIndex[valueHash]; exists {
		// Return existing token
		return formatToken(token, t.config.Format, t.config.Prefix, t.config.Suffix)
	}

	// Generate new token
	now := time.Now()
	tokenBytes := sha256.Sum256([]byte(value + now.String()))
	token := hex.EncodeToString(tokenBytes[:8]) // Use 8 bytes (16 hex chars)

	// Create expiration time if TTL is set
	var expiresAt time.Time
	if t.config.TokenTTL > 0 {
		expiresAt = now.Add(t.config.TokenTTL)
	}

	// Prepare original value for storage
	var originalValue string
	isEncrypted := false

	if t.config.EnableEncryption {
		// Encrypt the original value
		var err error
		originalValue, err = EncryptText(value)
		if err != nil {
			// Log error but continue without storing the original
			LogSecurityEvent("system", "tokenization_encryption_failed", SeverityWarning, requestID, map[string]string{
				"data_type": dataType,
				"error":     err.Error(),
			})
			originalValue = ""
		} else {
			isEncrypted = true
		}
	} else {
		// Store plaintext
		originalValue = value
	}

	// Create token entry
	tokenValue := TokenizedValue{
		Token:        token,
		CreatedAt:    now,
		ExpiresAt:    expiresAt,
		Original:     originalValue,
		IsEncrypted:  isEncrypted,
		DataType:     dataType,
		Format:       t.config.Format,
		OriginalHash: valueHash,
		CreatedBy:    requestID,
	}

	// Store in vault
	t.vault[token] = tokenValue
	t.reverseIndex[valueHash] = token

	// Log tokenization event
	LogSecurityEvent(requestID, "value_tokenized", SeverityInfo, requestID, map[string]string{
		"data_type":     dataType,
		"token_expires": expiresAt.Format(time.RFC3339),
	})

	// Persist to disk if enabled
	if t.config.EnablePersistence {
		go t.persistToDisk()
	}

	return formatToken(token, t.config.Format, t.config.Prefix, t.config.Suffix)
}

// formatToken formats a token according to the specified format
func formatToken(token string, format TokenFormat, prefix, suffix string) string {
	if format == FormatPrefix {
		return prefix + token + suffix
	}
	return token
}

// DetokenizeValue converts a token back to its original value
func (t *Tokenizer) DetokenizeValue(token, requestID string) (string, error) {
	// Extract token from formatted version
	rawToken := token
	if t.config.Format == FormatPrefix {
		rawToken = strings.TrimPrefix(token, t.config.Prefix)
		rawToken = strings.TrimSuffix(rawToken, t.config.Suffix)
	}

	t.lock.RLock()
	defer t.lock.RUnlock()

	// Look up token
	tv, exists := t.vault[rawToken]
	if !exists {
		return "", fmt.Errorf("token not found")
	}

	// Check if expired
	if !tv.ExpiresAt.IsZero() && tv.ExpiresAt.Before(time.Now()) {
		return "", fmt.Errorf("token expired")
	}

	// Check if original is stored
	if tv.Original == "" {
		return "", fmt.Errorf("original value not stored")
	}

	// Decrypt if needed
	if tv.IsEncrypted {
		original, err := DecryptText(tv.Original)
		if err != nil {
			// Log error
			LogSecurityEvent(requestID, "detokenization_decryption_failed", SeverityError, requestID, map[string]string{
				"data_type": tv.DataType,
				"error":     err.Error(),
			})
			return "", fmt.Errorf("failed to decrypt original value: %w", err)
		}

		// Log successful detokenization
		LogSecurityEvent(requestID, "value_detokenized", SeverityInfo, requestID, map[string]string{
			"data_type": tv.DataType,
		})

		return original, nil
	}

	// Log successful detokenization
	LogSecurityEvent(requestID, "value_detokenized", SeverityInfo, requestID, map[string]string{
		"data_type": tv.DataType,
	})

	return tv.Original, nil
}

// DetokenizeText replaces all tokens in a text with their original values
func (t *Tokenizer) DetokenizeText(text, requestID string) string {
	if text == "" {
		return ""
	}

	// For prefix format, use regex to find tokens
	if t.config.Format == FormatPrefix {
		// Simple string-based replacement for each token
		result := text

		t.lock.RLock()
		defer t.lock.RUnlock()

		for token, tv := range t.vault {
			// Skip if token has expired
			if !tv.ExpiresAt.IsZero() && tv.ExpiresAt.Before(time.Now()) {
				continue
			}

			// Skip if original is not stored
			if tv.Original == "" {
				continue
			}

			// Format token
			formattedToken := t.config.Prefix + token + t.config.Suffix

			// Check if token exists in text
			if strings.Contains(result, formattedToken) {
				// Get original value
				var original string
				var err error

				if tv.IsEncrypted {
					original, err = DecryptText(tv.Original)
					if err != nil {
						// Log error but continue with other tokens
						LogSecurityEvent(requestID, "detokenization_decryption_failed", SeverityWarning, requestID, map[string]string{
							"data_type": tv.DataType,
							"error":     err.Error(),
						})
						continue
					}
				} else {
					original = tv.Original
				}

				// Replace token with original value
				result = strings.ReplaceAll(result, formattedToken, original)
			}
		}

		return result
	}

	// For other formats, we'd need more complex logic
	return text
}

// RevokeToken revokes a specific token
func (t *Tokenizer) RevokeToken(token, requestID string) error {
	if !t.config.EnableRevocation {
		return fmt.Errorf("token revocation is not enabled")
	}

	// Extract token from formatted version
	rawToken := token
	if t.config.Format == FormatPrefix {
		rawToken = strings.TrimPrefix(token, t.config.Prefix)
		rawToken = strings.TrimSuffix(rawToken, t.config.Suffix)
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	// Look up token
	tv, exists := t.vault[rawToken]
	if !exists {
		return fmt.Errorf("token not found")
	}

	// Remove from vault and reverse index
	delete(t.vault, rawToken)
	delete(t.reverseIndex, tv.OriginalHash)

	// Log revocation
	LogSecurityEvent(requestID, "token_revoked", SeverityInfo, requestID, map[string]string{
		"data_type": tv.DataType,
	})

	// Persist changes
	if t.config.EnablePersistence {
		go t.persistToDisk()
	}

	return nil
}

// TokenizeValue returns a deterministic token for a given value (compatibility wrapper)
func TokenizeValue(value string) string {
	return GetTokenizer().TokenizeValue(value, "unknown", "system")
}

// DetokenizeText replaces known tokens in the text with their original values (compatibility wrapper)
func DetokenizeText(text string) string {
	return GetTokenizer().DetokenizeText(text, "system")
}
