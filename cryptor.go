package cryptor

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"io/ioutil"
	"math/rand"
	"os"
)

// EncryptFile encrypts a file with AES in CTR Mode.
// The key for AES is the SHA256 hash value of "password".
// IV is generated from rand.Read, so rand should be initialized with rand.Seed.
// IV will be written to the head of the output file.
func EncryptFile(inputFile, password, outputFile string) error {
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return err
	}

	// Create the key for AES from password by SHA256.
	hash := sha256.New()
	hash.Write([]byte(password))
	key := hash.Sum(nil)

	// Create the IV with random bytes
	iv := make([]byte, aes.BlockSize)
	n, err := rand.Read(iv)
	if err != nil || n != aes.BlockSize {
		return err
	}

	encryptedData, err := EncryptByAesInCtrMode(data, iv, key)
	if err != nil {
		return err
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}

	writer := bufio.NewWriter(file)
	// Put the IV at the head of the file so that it can be used at the time of decryption.
	writer.Write(iv)
	writer.Write(encryptedData)
	writer.Flush()

	return file.Close()
}

// DecryptFile decrypts a file encrypted by EncryptFile.
// The key for AES is the SHA256 hash value of "password".
// The IV is retrieved from the head of the inputFile.
func DecryptFile(inputFile string, password, outputFile string) error {
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return err
	}

	// Get the IV from the file.
	iv := data[:aes.BlockSize]

	// Create the key for AES from password by SHA256.
	hash := sha256.New()
	hash.Write([]byte(password))
	key := hash.Sum(nil)

	decryptedData, err := DecryptByAesInCtrMode(data[aes.BlockSize:], iv, key)
	if err != nil {
		return err
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}

	writer := bufio.NewWriter(file)
	writer.Write(decryptedData)
	writer.Flush()

	return file.Close()
}

// EncryptByAesInCtrMode encrypts data by AES in CTR mode with given IV and Key
func EncryptByAesInCtrMode(data []byte, iv []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	encryptedData := make([]byte, len(data))

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(encryptedData, data)

	return encryptedData, nil
}

// DecryptByAesInCtrMode decrypts data by AES in CTR mode with given IV and Key.
// Internally this just calls EncryptByAesInCtrMode.
func DecryptByAesInCtrMode(data []byte, iv []byte, key []byte) ([]byte, error) {
	return EncryptByAesInCtrMode(data, iv, key)
}

// EncryptByAesInGcmMode encrypts data by AES in GCM mode with given nonce, key and additionalData.
// Panics if the size of nonce does not match the GCM's default nonce size (12).
func EncryptByAesInGcmMode(data []byte, nonce []byte, key []byte, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ahead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	encryptedData := ahead.Seal(nil, nonce, data, additionalData)

	return encryptedData, nil
}

// DecryptByAesInGcmMode decrypts data by AES in GCM mode with given nonce, key and additionalData.
// Panics if the size of nonce does not match the GCM's default nonce size (12).
func DecryptByAesInGcmMode(encryptedData []byte, nonce []byte, key []byte, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ahead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return ahead.Open(nil, nonce, encryptedData, additionalData)
}
