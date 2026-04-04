// Package aes provides AES-256-GCM authenticated encryption.
package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// Encrypt performs AES-256-GCM encryption with a random nonce prepended to the ciphertext.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt performs AES-256-GCM decryption. The nonce is expected to be prepended to the ciphertext.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
}

// KeylessCipher provides AES-256-GCM encryption with the key passed per-call.
type KeylessCipher struct{}

// EncryptURLString encrypts plaintext and returns a base64 URL-safe encoded string.
func (KeylessCipher) EncryptURLString(key []byte, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	ct, err := Encrypt(key, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

// DecryptURLString decodes a base64 URL-safe string and decrypts it.
func (KeylessCipher) DecryptURLString(key []byte, encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	ct, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	plain, err := Decrypt(key, ct)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// Cipher provides AES-256-GCM encryption with a fixed key and cached GCM instance
type Cipher struct{ gcm cipher.AEAD }

// NewCipher creates a Cipher with the given key.
func NewCipher(key []byte) (*Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{gcm: gcm}, nil
}

// Encrypt encrypts plaintext using the cipher's cached GCM instance.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return c.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts ciphertext using the cipher's cached GCM instance.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < c.gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return c.gcm.Open(nil, ciphertext[:c.gcm.NonceSize()], ciphertext[c.gcm.NonceSize():], nil)
}

// EncryptString encrypts plaintext and returns a base64-encoded string.
// Returns an empty string for empty input.
func (c *Cipher) EncryptString(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	ct, err := c.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

// DecryptString decodes a base64 string and decrypts it.
// Returns an empty string for empty input.
func (c *Cipher) DecryptString(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	ct, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	plain, err := c.Decrypt(ct)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
