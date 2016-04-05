package cryptor

import (
	"bytes"
	"crypto/aes"
	"io/ioutil"
	"os"
	"testing"
)

func TestAesCtr(t *testing.T) {
	originalData := []byte("Hello, World!")
	iv := make([]byte, aes.BlockSize)
	key := []byte("0123456789ABCDEF")

	t.Logf("Original  data : %s (%v)", string(originalData), originalData)

	encrypted, err := EncryptByAesInCtrMode(originalData, iv, key)
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("Encrypted data : %v", encrypted)

	decrypted, err := DecryptByAesInCtrMode(encrypted, iv, key)
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("Decrypted data : %s (%v)", string(decrypted), decrypted)

	if !bytes.Equal(originalData, decrypted) {
		t.Fatal("Original data and decrypted data do not match.")
	}
}

func TestAesGcm(t *testing.T) {
	originalData := []byte("Hello, World!")
	additionalData := []byte("GCM")
	nonce := make([]byte, 12)
	key := []byte("0123456789ABCDEF")
	key2 := []byte("0123456789ABCDEE")

	t.Logf("Original  data : %s (%v)", string(originalData), originalData)

	encrypted, err := EncryptByAesInGcmMode(originalData, nonce, key, additionalData)
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("Encrypted data : %v", encrypted)

	decrypted, err := DecryptByAesInGcmMode(encrypted, nonce, key2, additionalData)

	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("Decrypted data : %s (%v)", string(decrypted), decrypted)

	if !bytes.Equal(originalData, decrypted) {
		t.Fatal("Original data and decrypted data do not match.")
	}
}

func TestEncryptFile(t *testing.T) {

	sourceFile := "cryptor.go"
	encryptedFile := "cryptor.go.encrypted"
	decryptedFile := "cryptor.go.decrypted"
	password := "password"

	defer func() {
		os.Remove("cryptor.go.encrypted")
		os.Remove("cryptor.go.decrypted")
	}()

	err := EncryptFile(sourceFile, password, encryptedFile)
	if err != nil {
		t.Fatal(err.Error())
	}
	err = DecryptFile(encryptedFile, password, decryptedFile)
	if err != nil {
		t.Fatal(err.Error())
	}

	sourceData, err := ioutil.ReadFile(sourceFile)
	if err != nil {
		t.Fatal(err.Error())
	}

	decryptedData, err := ioutil.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err.Error())
	}

	if !bytes.Equal(sourceData, decryptedData) {
		t.Fatal("Original data and decrypted data do not match.")
	}
}
