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
	gcm := aesgcm.Cipher{}
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
	gcm := aesgcm.Cipher{}
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
	gcm := aesgcm.Cipher{}
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
	gcm := aesgcm.Cipher{}
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
	gcm := aesgcm.Cipher{}
	key := testKey(t)

	if _, err := gcm.Decrypt(key, []byte("short")); err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

func TestGCM_InvalidKeySize_Fails(t *testing.T) {
	gcm := aesgcm.Cipher{}
	badKey := []byte("too-short")

	if _, err := gcm.Encrypt(badKey, []byte("data")); err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestGCM_UniqueNonces(t *testing.T) {
	gcm := aesgcm.Cipher{}
	key := testKey(t)
	plaintext := []byte("same input")

	ct1, _ := gcm.Encrypt(key, plaintext)
	ct2, _ := gcm.Encrypt(key, plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of the same plaintext should produce different ciphertext (unique nonces)")
	}
}
