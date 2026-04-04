package aes_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	aesgcm "github.com/travisbale/mirage/internal/crypto/aes"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestGCM_RoundTrip(t *testing.T) {
	gcm := aesgcm.KeylessCipher{}
	key := testKey(t)
	plaintext := []byte("hello world")

	ciphertext, err := gcm.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	decrypted, err := gcm.Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypt = %q, want %q", decrypted, plaintext)
	}
}

func TestGCM_EmptyPlaintext(t *testing.T) {
	gcm := aesgcm.KeylessCipher{}
	key := testKey(t)

	ciphertext, err := gcm.Encrypt(key, []byte{})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	decrypted, err := gcm.Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %q", decrypted)
	}
}

func TestGCM_WrongKey_Fails(t *testing.T) {
	gcm := aesgcm.KeylessCipher{}
	key1 := testKey(t)
	key2 := testKey(t)

	ciphertext, err := gcm.Encrypt(key1, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := gcm.Decrypt(key2, ciphertext); err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestGCM_TamperedCiphertext_Fails(t *testing.T) {
	gcm := aesgcm.KeylessCipher{}
	key := testKey(t)

	ciphertext, err := gcm.Encrypt(key, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	ciphertext[len(ciphertext)-1] ^= 0xff // flip last byte

	if _, err := gcm.Decrypt(key, ciphertext); err == nil {
		t.Fatal("expected error decrypting tampered ciphertext")
	}
}

func TestGCM_TooShortCiphertext_Fails(t *testing.T) {
	gcm := aesgcm.KeylessCipher{}
	key := testKey(t)

	if _, err := gcm.Decrypt(key, []byte("short")); err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

func TestGCM_InvalidKeySize_Fails(t *testing.T) {
	gcm := aesgcm.KeylessCipher{}
	badKey := []byte("too-short")

	if _, err := gcm.Encrypt(badKey, []byte("data")); err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestGCM_UniqueNonces(t *testing.T) {
	gcm := aesgcm.KeylessCipher{}
	key := testKey(t)
	plaintext := []byte("same input")

	ct1, _ := gcm.Encrypt(key, plaintext)
	ct2, _ := gcm.Encrypt(key, plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of the same plaintext should produce different ciphertext (unique nonces)")
	}
}

// --- Cipher (stateful, string-oriented) ---

func newTestCipher(t *testing.T) *aesgcm.Cipher {
	t.Helper()
	c, err := aesgcm.NewCipher(testKey(t))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func TestCipher_EncryptString_RoundTrip(t *testing.T) {
	c := newTestCipher(t)

	encrypted, err := c.EncryptString("hello world")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	if encrypted == "hello world" {
		t.Fatal("encrypted should differ from plaintext")
	}

	decrypted, err := c.DecryptString(encrypted)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if decrypted != "hello world" {
		t.Errorf("DecryptString = %q, want %q", decrypted, "hello world")
	}
}

func TestCipher_EncryptString_EmptyPassthrough(t *testing.T) {
	c := newTestCipher(t)

	encrypted, err := c.EncryptString("")
	if err != nil {
		t.Fatalf("EncryptString empty: %v", err)
	}
	if encrypted != "" {
		t.Errorf("expected empty string passthrough, got %q", encrypted)
	}

	decrypted, err := c.DecryptString("")
	if err != nil {
		t.Fatalf("DecryptString empty: %v", err)
	}
	if decrypted != "" {
		t.Errorf("expected empty string passthrough, got %q", decrypted)
	}
}

func TestCipher_DecryptString_WrongKey(t *testing.T) {
	c1 := newTestCipher(t)
	c2 := newTestCipher(t)

	encrypted, err := c1.EncryptString("secret")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	if _, err := c2.DecryptString(encrypted); err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}
