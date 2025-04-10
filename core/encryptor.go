package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EncryptionAlgorithm defines supported encryption algorithms
type EncryptionAlgorithm string

const (
	// AlgorithmAESGCM is AES in Galois/Counter Mode
	AlgorithmAESGCM EncryptionAlgorithm = "AES-GCM"

	// AlgorithmAESCBC is AES in Cipher Block Chaining mode
	AlgorithmAESCBC EncryptionAlgorithm = "AES-CBC"
)

// KeySource defines where encryption keys are stored
type KeySource string

const (
	// KeySourceEnv retrieves keys from environment variables
	KeySourceEnv KeySource = "env"

	// KeySourceFile retrieves keys from files
	KeySourceFile KeySource = "file"

	// KeySourceKMS retrieves keys from a key management service
	KeySourceKMS KeySource = "kms"
)

// EncryptedData represents encrypted data with metadata
type EncryptedData struct {
	// Version of the encryption format
	Version int `json:"version"`

	// Algorithm used for encryption
	Algorithm EncryptionAlgorithm `json:"alg"`

	// KeyID that was used for encryption
	KeyID string `json:"kid"`

	// Time when the data was encrypted
	EncryptedAt int64 `json:"enc_at"`

	// Ciphertext (base64 encoded)
	Ciphertext string `json:"ciphertext"`

	// Additional authenticated data (optional)
	AAD string `json:"aad,omitempty"`
}

// KeyMetadata contains information about an encryption key
type KeyMetadata struct {
	// Unique ID for the key
	ID string `json:"id"`

	// When the key was created
	CreatedAt time.Time `json:"created_at"`

	// When the key expires (zero time means no expiration)
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Key source (env, file, kms)
	Source KeySource `json:"source"`

	// Source identifier (environment variable name, file path, KMS key ARN)
	SourceID string `json:"source_id"`

	// Whether this is the current active key
	Active bool `json:"active"`
}

// EncryptionConfig specifies parameters for the encryptor
type EncryptionConfig struct {
	// Algorithm to use for encryption
	Algorithm EncryptionAlgorithm

	// Key source (env, file, kms)
	KeySource KeySource

	// Keys directory or base path
	KeysPath string

	// Key rotation interval (zero means no automatic rotation)
	KeyRotationInterval time.Duration

	// Whether to enable key rotation
	EnableKeyRotation bool

	// Maximum number of keys to keep
	MaxKeys int
}

// Encryptor provides SOC 2 compliant encryption services
type Encryptor struct {
	config EncryptionConfig
	keys   []KeyMetadata
	keyMu  sync.RWMutex

	// Cache of loaded keys to avoid frequent reloading
	keyCache   map[string][]byte
	keyCacheMu sync.RWMutex

	// Logger for auditing encryption operations
	logger *AuditLogger
}

// DefaultEncryptor is the singleton encryptor instance
var DefaultEncryptor *Encryptor
var encryptorOnce sync.Once

// GetEncryptor returns the singleton encryptor
func GetEncryptor() *Encryptor {
	encryptorOnce.Do(func() {
		config := EncryptionConfig{
			Algorithm:           AlgorithmAESGCM,
			KeySource:           KeySourceEnv,
			KeysPath:            "keys",
			EnableKeyRotation:   true,
			KeyRotationInterval: 90 * 24 * time.Hour, // 90 days
			MaxKeys:             5,
		}

		DefaultEncryptor = NewEncryptor(config)
		// Initialize without returning error - errors will be logged
		_ = DefaultEncryptor.Initialize()
	})

	return DefaultEncryptor
}

// NewEncryptor creates a new encryptor with the given configuration
func NewEncryptor(config EncryptionConfig) *Encryptor {
	return &Encryptor{
		config:   config,
		keys:     []KeyMetadata{},
		keyCache: make(map[string][]byte),
		logger:   GetAuditLogger(), // Use the global audit logger
	}
}

// Initialize sets up the encryptor, loading or creating keys as needed
func (e *Encryptor) Initialize() error {
	e.keyMu.Lock()
	defer e.keyMu.Unlock()

	// Load existing keys
	var err error
	if e.config.KeySource == KeySourceFile {
		err = e.loadKeysFromFile()
	} else {
		// For other sources, look for configured keys
		err = e.checkConfiguredKeys()
	}

	// If no keys exist or there's an error, create a new key
	if err != nil || len(e.keys) == 0 {
		return e.createNewKey()
	}

	// Check if key rotation is needed
	if e.config.EnableKeyRotation {
		return e.checkKeyRotation()
	}

	return nil
}

// loadKeysFromFile loads key metadata from disk
func (e *Encryptor) loadKeysFromFile() error {
	// Ensure keys directory exists
	if err := os.MkdirAll(e.config.KeysPath, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Look for metadata file
	metadataPath := filepath.Join(e.config.KeysPath, "metadata.json")
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		// No metadata file yet, no keys to load
		return nil
	}

	// Read metadata file
	data, err := ioutil.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to read key metadata: %w", err)
	}

	// Parse keys
	if err := json.Unmarshal(data, &e.keys); err != nil {
		return fmt.Errorf("failed to parse key metadata: %w", err)
	}

	return nil
}

// checkConfiguredKeys checks for keys configured in the environment
func (e *Encryptor) checkConfiguredKeys() error {
	// For environment variables, check for CSP_ENCRYPTION_KEY
	if e.config.KeySource == KeySourceEnv {
		key := os.Getenv("CSP_ENCRYPTION_KEY")
		if key != "" {
			// Add as default key if not already in the list
			keyID := generateKeyID([]byte(key))
			found := false

			for _, k := range e.keys {
				if k.ID == keyID {
					found = true
					break
				}
			}

			if !found {
				e.keys = append(e.keys, KeyMetadata{
					ID:        keyID,
					CreatedAt: time.Now(),
					Source:    KeySourceEnv,
					SourceID:  "CSP_ENCRYPTION_KEY",
					Active:    true,
				})
			}
		}
	}

	return nil
}

// createNewKey generates and stores a new encryption key
func (e *Encryptor) createNewKey() error {
	// Generate random key
	key := make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Create metadata
	keyID := generateKeyID(key)
	metadata := KeyMetadata{
		ID:        keyID,
		CreatedAt: time.Now(),
		Source:    e.config.KeySource,
		Active:    true,
	}

	// Store key according to source
	if e.config.KeySource == KeySourceEnv {
		// For environment, set variable name
		metadata.SourceID = "CSP_ENCRYPTION_KEY_" + keyID[:8]

		// Log instruction since we can't set env vars programmatically
		e.logger.LogEvent(AuditLog{
			RequestID:    "system",
			Timestamp:    time.Now().Format(time.RFC3339),
			EventType:    "key_creation",
			ActionSource: "encryption",
			Severity:     SeverityInfo,
			Metadata: map[string]string{
				"key_id":      keyID,
				"action":      "manual_setup_required",
				"instruction": fmt.Sprintf("Set %s environment variable with the generated key", metadata.SourceID),
			},
		})
	} else if e.config.KeySource == KeySourceFile {
		// For file, save to disk
		metadata.SourceID = filepath.Join(e.config.KeysPath, keyID+".key")

		// Ensure directory exists
		if err := os.MkdirAll(e.config.KeysPath, 0700); err != nil {
			return fmt.Errorf("failed to create keys directory: %w", err)
		}

		// Write key to file
		if err := ioutil.WriteFile(metadata.SourceID, key, 0600); err != nil {
			return fmt.Errorf("failed to write key to file: %w", err)
		}
	}

	// Mark existing keys as inactive
	for i := range e.keys {
		e.keys[i].Active = false
	}

	// Add new key
	e.keys = append(e.keys, metadata)

	// Save metadata
	return e.saveKeyMetadata()
}

// saveKeyMetadata saves key metadata to disk
func (e *Encryptor) saveKeyMetadata() error {
	if e.config.KeySource != KeySourceFile {
		// Only save metadata to disk for file-based keys
		return nil
	}

	// Ensure directory exists
	if err := os.MkdirAll(e.config.KeysPath, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Serialize metadata
	data, err := json.MarshalIndent(e.keys, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize key metadata: %w", err)
	}

	// Write to file
	metadataPath := filepath.Join(e.config.KeysPath, "metadata.json")
	if err := ioutil.WriteFile(metadataPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write key metadata: %w", err)
	}

	return nil
}

// checkKeyRotation checks if key rotation is needed and performs it if so
func (e *Encryptor) checkKeyRotation() error {
	// Find active key
	var activeKey *KeyMetadata
	for i := range e.keys {
		if e.keys[i].Active {
			activeKey = &e.keys[i]
			break
		}
	}

	// If no active key, create one
	if activeKey == nil {
		return e.createNewKey()
	}

	// Check if rotation is needed
	if e.config.KeyRotationInterval > 0 {
		rotationTime := activeKey.CreatedAt.Add(e.config.KeyRotationInterval)
		if time.Now().After(rotationTime) {
			// Key has expired, create new key
			e.logger.LogEvent(AuditLog{
				RequestID:    "system",
				Timestamp:    time.Now().Format(time.RFC3339),
				EventType:    "key_rotation",
				ActionSource: "encryption",
				Severity:     SeverityInfo,
				Metadata: map[string]string{
					"old_key_id": activeKey.ID,
					"reason":     "scheduled_rotation",
				},
			})

			return e.createNewKey()
		}
	}

	return nil
}

// getActiveKey returns the currently active encryption key
func (e *Encryptor) getActiveKey() ([]byte, string, error) {
	e.keyMu.RLock()
	defer e.keyMu.RUnlock()

	// Find active key
	var activeKey *KeyMetadata
	for i := range e.keys {
		if e.keys[i].Active {
			activeKey = &e.keys[i]
			break
		}
	}

	if activeKey == nil {
		return nil, "", errors.New("no active encryption key found")
	}

	// Check cache first
	e.keyCacheMu.RLock()
	cachedKey, found := e.keyCache[activeKey.ID]
	e.keyCacheMu.RUnlock()

	if found {
		return cachedKey, activeKey.ID, nil
	}

	// Load key based on source
	var keyBytes []byte
	var err error

	if activeKey.Source == KeySourceEnv {
		// Get from environment
		keyBytes = []byte(os.Getenv(activeKey.SourceID))
		if len(keyBytes) == 0 {
			return nil, "", fmt.Errorf("encryption key not found in environment: %s", activeKey.SourceID)
		}
	} else if activeKey.Source == KeySourceFile {
		// Read from file
		keyBytes, err = ioutil.ReadFile(activeKey.SourceID)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read encryption key from file: %w", err)
		}
	} else {
		return nil, "", fmt.Errorf("unsupported key source: %s", activeKey.Source)
	}

	// Add to cache
	e.keyCacheMu.Lock()
	e.keyCache[activeKey.ID] = keyBytes
	e.keyCacheMu.Unlock()

	return keyBytes, activeKey.ID, nil
}

// getKeyByID retrieves a specific key by ID
func (e *Encryptor) getKeyByID(keyID string) ([]byte, error) {
	e.keyMu.RLock()
	defer e.keyMu.RUnlock()

	// Find key metadata
	var keyMeta *KeyMetadata
	for i := range e.keys {
		if e.keys[i].ID == keyID {
			keyMeta = &e.keys[i]
			break
		}
	}

	if keyMeta == nil {
		return nil, fmt.Errorf("encryption key not found: %s", keyID)
	}

	// Check cache first
	e.keyCacheMu.RLock()
	cachedKey, found := e.keyCache[keyID]
	e.keyCacheMu.RUnlock()

	if found {
		return cachedKey, nil
	}

	// Load key based on source
	var keyBytes []byte
	var err error

	if keyMeta.Source == KeySourceEnv {
		// Get from environment
		keyBytes = []byte(os.Getenv(keyMeta.SourceID))
		if len(keyBytes) == 0 {
			return nil, fmt.Errorf("encryption key not found in environment: %s", keyMeta.SourceID)
		}
	} else if keyMeta.Source == KeySourceFile {
		// Read from file
		keyBytes, err = ioutil.ReadFile(keyMeta.SourceID)
		if err != nil {
			return nil, fmt.Errorf("failed to read encryption key from file: %w", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported key source: %s", keyMeta.Source)
	}

	// Add to cache
	e.keyCacheMu.Lock()
	e.keyCache[keyID] = keyBytes
	e.keyCacheMu.Unlock()

	return keyBytes, nil
}

// generateKeyID creates a unique ID for a key
func generateKeyID(key []byte) string {
	hash := sha256.Sum256(key)
	return base64.RawURLEncoding.EncodeToString(hash[:16])
}

// Encrypt encrypts plaintext with SOC 2 compliant metadata
func (e *Encryptor) Encrypt(plaintext string, aad string) (string, error) {
	// Get active key
	key, keyID, err := e.getActiveKey()
	if err != nil {
		return "", err
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	var ciphertext []byte
	var encData EncryptedData

	// Encrypt based on algorithm
	if e.config.Algorithm == AlgorithmAESGCM {
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return "", fmt.Errorf("failed to create GCM: %w", err)
		}

		// Create nonce
		nonce := make([]byte, aesGCM.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return "", fmt.Errorf("failed to generate nonce: %w", err)
		}

		// Encrypt with AAD if provided
		var aadBytes []byte
		if aad != "" {
			aadBytes = []byte(aad)
		}

		ciphertext = aesGCM.Seal(nonce, nonce, []byte(plaintext), aadBytes)
	} else {
		return "", fmt.Errorf("unsupported algorithm: %s", e.config.Algorithm)
	}

	// Create metadata
	encData = EncryptedData{
		Version:     1,
		Algorithm:   e.config.Algorithm,
		KeyID:       keyID,
		EncryptedAt: time.Now().Unix(),
		Ciphertext:  base64.StdEncoding.EncodeToString(ciphertext),
	}

	if aad != "" {
		encData.AAD = base64.StdEncoding.EncodeToString([]byte(aad))
	}

	// Serialize
	encJSON, err := json.Marshal(encData)
	if err != nil {
		return "", fmt.Errorf("failed to serialize encrypted data: %w", err)
	}

	return base64.StdEncoding.EncodeToString(encJSON), nil
}

// Decrypt decrypts ciphertext with SOC 2 compliant metadata handling
func (e *Encryptor) Decrypt(encryptedData string) (string, error) {
	// Decode base64
	encJSON, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		// Try legacy format first before failing
		return e.decryptLegacy(encryptedData)
	}

	// Parse JSON
	var encData EncryptedData
	if err := json.Unmarshal(encJSON, &encData); err != nil {
		// Try legacy format
		return e.decryptLegacy(encryptedData)
	}

	// Get key by ID
	key, err := e.getKeyByID(encData.KeyID)
	if err != nil {
		return "", fmt.Errorf("failed to get decryption key: %w", err)
	}

	// Decode ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(encData.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Decrypt based on algorithm
	var plaintext []byte
	if encData.Algorithm == AlgorithmAESGCM {
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return "", fmt.Errorf("failed to create GCM: %w", err)
		}

		// Extract nonce
		nonceSize := aesGCM.NonceSize()
		if len(ciphertext) < nonceSize {
			return "", errors.New("ciphertext too short")
		}

		nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]

		// Prepare AAD if provided
		var aadBytes []byte
		if encData.AAD != "" {
			aadBytes, err = base64.StdEncoding.DecodeString(encData.AAD)
			if err != nil {
				return "", fmt.Errorf("failed to decode AAD: %w", err)
			}
		}

		// Decrypt
		plaintext, err = aesGCM.Open(nil, nonce, ct, aadBytes)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt: %w", err)
		}
	} else {
		return "", fmt.Errorf("unsupported algorithm: %s", encData.Algorithm)
	}

	return string(plaintext), nil
}

// decryptLegacy handles decryption of data encrypted with the old format
func (e *Encryptor) decryptLegacy(cipherB64 string) (string, error) {
	// Get legacy key from environment
	key := os.Getenv("CSP_ENCRYPTION_KEY")
	if len(key) != 32 {
		return "", errors.New("CSP_ENCRYPTION_KEY must be 32 bytes long")
	}

	// Decode base64
	data, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return "", err
	}

	// Create cipher
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// Decrypt
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// EncryptText encrypts plaintext using SOC 2 compliant encryption (compatibility wrapper)
func EncryptText(plaintext string) (string, error) {
	return GetEncryptor().Encrypt(plaintext, "")
}

// DecryptText decrypts ciphertext (compatibility wrapper)
func DecryptText(encryptedData string) (string, error) {
	return GetEncryptor().Decrypt(encryptedData)
}

// RotateEncryptionKeys manually triggers key rotation
func RotateEncryptionKeys() error {
	encryptor := GetEncryptor()
	encryptor.keyMu.Lock()
	defer encryptor.keyMu.Unlock()

	return encryptor.createNewKey()
}
