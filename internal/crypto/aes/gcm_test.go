package aes_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/travisbale/mirage/internal/crypto/aes"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestEncrypt_RoundTrip(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("hello world")

	ciphertext, err := aes.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	decrypted, err := aes.Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypt = %q, want %q", decrypted, plaintext)
	}
}

func TestEncrypt_EmptyPlaintext(t *testing.T) {
	key := testKey(t)

	ciphertext, err := aes.Encrypt(key, []byte{})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	decrypted, err := aes.Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %q", decrypted)
	}
}

func TestDecrypt_WrongKey_Fails(t *testing.T) {
	key1 := testKey(t)
	key2 := testKey(t)

	ciphertext, err := aes.Encrypt(key1, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := aes.Decrypt(key2, ciphertext); err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestDecrypt_TamperedCiphertext_Fails(t *testing.T) {
	key := testKey(t)

	ciphertext, err := aes.Encrypt(key, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	ciphertext[len(ciphertext)-1] ^= 0xff // flip last byte

	if _, err := aes.Decrypt(key, ciphertext); err == nil {
		t.Fatal("expected error decrypting tampered ciphertext")
	}
}

func TestDecrypt_TooShortCiphertext_Fails(t *testing.T) {
	key := testKey(t)

	if _, err := aes.Decrypt(key, []byte("short")); err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

func TestEncrypt_InvalidKeySize_Fails(t *testing.T) {
	badKey := []byte("too-short")

	if _, err := aes.Encrypt(badKey, []byte("data")); err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestEncrypt_UniqueNonces(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("same input")

	ct1, _ := aes.Encrypt(key, plaintext)
	ct2, _ := aes.Encrypt(key, plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of the same plaintext should produce different ciphertext (unique nonces)")
	}
}

// --- Cipher (stateful, cached GCM) ---

func newTestCipher(t *testing.T) *aes.Cipher {
	t.Helper()
	c, err := aes.NewCipher(testKey(t))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func TestCipher_RoundTrip(t *testing.T) {
	c := newTestCipher(t)
	plaintext := []byte("hello world")

	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	decrypted, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypt = %q, want %q", decrypted, plaintext)
	}
}

func TestCipher_WrongKey(t *testing.T) {
	c1 := newTestCipher(t)
	c2 := newTestCipher(t)

	ciphertext, err := c1.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := c2.Decrypt(ciphertext); err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}
