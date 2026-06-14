package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"sync"
)

// Manager manages the active RSA signing key pair.
type Manager struct {
	mu         sync.RWMutex
	privateKey *rsa.PrivateKey
	keyID      string
}

// New creates a new Manager with the given key ID.
func New(keyID string) *Manager {
	return &Manager{keyID: keyID}
}

// LoadOrGenerate loads a PEM-encoded RSA private key from path. If the file
// does not exist, a new RSA-2048 key is generated and persisted to path.
func (m *Manager) LoadOrGenerate(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if err == nil {
		// File exists — decode and parse. Accept both PKCS1 and PKCS8.
		block, _ := pem.Decode(data)
		if block == nil {
			return errors.New("keys: no PEM block found in " + path)
		}
		var key *rsa.PrivateKey
		switch block.Type {
		case "RSA PRIVATE KEY":
			var parseErr error
			key, parseErr = x509.ParsePKCS1PrivateKey(block.Bytes)
			if parseErr != nil {
				return parseErr
			}
		case "PRIVATE KEY":
			parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
			if parseErr != nil {
				return parseErr
			}
			var ok bool
			key, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				return errors.New("keys: PKCS8 key is not RSA in " + path)
			}
		default:
			return errors.New("keys: unsupported PEM block type " + block.Type + " in " + path)
		}
		m.privateKey = key
		return nil
	}

	// File does not exist — generate a new key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	derBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derBytes,
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, block); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	m.privateKey = key
	return nil
}

// PrivateKey returns the active RSA private key.
func (m *Manager) PrivateKey() *rsa.PrivateKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.privateKey
}

// PublicKey returns the active RSA public key.
func (m *Manager) PublicKey() *rsa.PublicKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return &m.privateKey.PublicKey
}

// KeyID returns the active key ID.
func (m *Manager) KeyID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.keyID
}
