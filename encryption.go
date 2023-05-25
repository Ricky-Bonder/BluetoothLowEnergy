package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"

	log "github.com/sirupsen/logrus"
)

var g_dev_pubkey [32]byte
var g_dev_privkey [32]byte
var g_randomBytes = make([]byte, 16)
var g_session_key = make([]byte, 0)

/*
GenerateKey generates a public private key pair using Curve25519.
*/
func GenerateKey() error {

	_, err := io.ReadFull(rand.Reader, g_dev_privkey[:])
	if err != nil {
		return err
	}

	// @RO inutile?
	// g_dev_privkey[0] &= 0xF8
	// g_dev_privkey[31] &= 0x7F
	// g_dev_privkey[31] |= 0x40

	curve25519.ScalarBaseMult(&g_dev_pubkey, &g_dev_privkey)
	return nil
}

/*
GenerateSharedSecret generates the shared secret with a given public private key pair.
*/
func GenerateSharedSecretNoPop(priv, pub []byte) []byte {
	var secret []byte

	secret, _ = curve25519.X25519(priv, pub)

	return secret[:]

}

func GenerateSharedSecretWithPoP(priv, pub []byte, pop string) error {

	fmt.Printf("priv: %s, pub: %s, pop: %s\n", string(priv), string(pub), string(pop))
	var secret []byte

	secret, _ = curve25519.X25519(priv, pub)

	// Hash PoP value using SHA256
	popHash := sha256.Sum256([]byte(pop))

	// XOR shared secret with hashed PoP value
	for i := 0; i < 32; i++ {
		secret[i] ^= popHash[i]
	}

	g_session_key = secret

	return nil
}

// Generate 32 random bytes
func GenarateInitializationVector() error {
	if _, err := rand.Read(g_randomBytes); err != nil {
		log.Errorf("Error generating random bytes: %v", err)
		return err
	}
	return nil
}

func decryptToken(cipherTextByte []byte, sessionKey []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	log.Debug("block size: ", block.BlockSize(), " - iv: ", len(g_randomBytes))

	// Create a new AES-CTR mode cipher with the block
	aesctr := cipher.NewCTR(block, g_randomBytes)
	if err != nil {
		return nil, err
	}

	var dstPlainTextByte []byte = make([]byte, 0)
	// DECRYPT DATA
	aesctr.XORKeyStream(dstPlainTextByte, cipherTextByte)
	return dstPlainTextByte, nil
}

func encryptToken2(plainTextByte []byte, sessionKey []byte, nonce []byte) (string, error) {
	// GET CIPHER BLOCK USING KEY
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return "", err
	}

	// GET CTR
	aesctr := cipher.NewCTR(block, nonce)
	if err != nil {
		return "", err
	}

	var dstCipherTextByte []byte = make([]byte, 0)
	// ENCRYPT DATA
	aesctr.XORKeyStream(dstCipherTextByte, plainTextByte)

	// RETURN String Base64 encoded
	cipherText := "S3," + base64.StdEncoding.EncodeToString(dstCipherTextByte)
	return cipherText, nil
}
