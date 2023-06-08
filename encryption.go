package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	random "math/rand"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	log "github.com/sirupsen/logrus"
)

var g_dev_pubkey [32]byte
var g_dev_privkey [32]byte
var g_randomBytes = make([]byte, 16)
var g_shared_key = make([]byte, 0)

type IHandshake interface {
	selector(dataFromClient []byte)
}

type myHandshake struct{}

func (m myHandshake) selector(bytesFromClient []byte) ([]byte, error) {
	parsedMessage := strings.SplitN(string(bytesFromClient), ",", 2)
	log.Info("base64 body of incoming message is ", parsedMessage[1])

	// Decode the encoded key using base64 decoding
	decodedData, err := base64.StdEncoding.DecodeString(parsedMessage[1])
	if err != nil {
		log.Errorf("Error: %v Decoding: %s ", err, string(bytesFromClient))
		return nil, err
	}

	log.Infof("decoded incoming message as string: %v ", decodedData)

	if strings.Contains(parsedMessage[0], "S0") {
		log.Debug("Decoding client's message S0")
		err := handleSessionEnstablishment(b, []byte(decodedData))
		if err != nil {
			return nil, err
		}
	} else if strings.Contains(parsedMessage[0], "S2") {
		log.Debug("Decoding client's message S2")
		err := handleSessionVerify(b, []byte(decodedData))
		if err != nil {
			return nil, err
		}
	} else {
		log.Debug("Decoded message doesn't match with any handshake step.")
		return nil, err
	}
	return nil, nil
}

/*
GenerateKey generates a public-private key pair using the Curve25519 algorithm.
*/
func GenerateKey() error {

	_, err := io.ReadFull(rand.Reader, g_dev_privkey[:])
	if err != nil {
		return err
	}

	curve25519.ScalarBaseMult(&g_dev_pubkey, &g_dev_privkey)
	return nil
}

func GenerateSharedKeyWithPoP(priv, pub []byte, pop string) error {

	fmt.Printf("AHU priv: %s, Client pub: %s, PoP: %s\n", base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), string(pop))
	fmt.Printf("client pub key hex: %v", hex.EncodeToString(pub))
	var secret []byte

	secret, _ = curve25519.X25519(priv, pub)

	// Hash PoP value using SHA256
	popHash := sha256.Sum256([]byte(pop))

	// XOR shared secret with hashed PoP value
	for i := 0; i < 32; i++ {
		secret[i] ^= popHash[i]
	}

	g_shared_key = secret
	log.Debug("Generated Session Key HEX: ", hex.EncodeToString(secret))

	return nil
}

// Generate 32 random bytes
func GenarateInitializationVector() error {
	if _, err := rand.Read(g_randomBytes); err != nil {
		log.Errorf("Error generating random bytes: %v", err)
		return err
	}
	log.Debug("@@@ IV: ", hex.EncodeToString(g_randomBytes))
	return nil
}

/*
* Decrypts a []byte token using algorithm AES-256-Counter-mode (using the IV)
 */
func DecryptToken(cipherTextByte []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(g_shared_key)
	if err != nil {
		return nil, err
	}

	// Create a new AES-CTR mode cipher with the block
	aesctr := cipher.NewCTR(block, g_randomBytes)
	if err != nil {
		return nil, err
	}

	var dstPlainTextByte []byte = make([]byte, 32)
	// DECRYPT DATA
	aesctr.XORKeyStream(dstPlainTextByte, cipherTextByte)
	return dstPlainTextByte, nil
}

/*
* Encrypts a []byte token using algorithm AES-256-Counter-mode (using the IV)
 */
func EncryptToken(plainTextByte []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(g_shared_key)
	if err != nil {
		return nil, err
	}

	// Create a new AES-CTR mode cipher with the block
	aesctr := cipher.NewCTR(block, g_randomBytes)
	if err != nil {
		return nil, err
	}

	var dstCipherTextByte []byte = make([]byte, len(plainTextByte))
	// ENCRYPT DATA
	aesctr.XORKeyStream(dstCipherTextByte, plainTextByte)

	// RETURN encoded byte array containing the dev_verify for client
	return dstCipherTextByte, nil
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func generatePoP(length int) string {
	random.Seed(time.Now().UnixNano())

	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = charset[random.Intn(len(charset))]
	}
	return string(result)
}
