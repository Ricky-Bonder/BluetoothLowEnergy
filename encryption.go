package main

import (
	"bytes"
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

type IHandshake interface {
	Selector(dataFromClient []byte) ([]byte, error)
}

type Curve25519Algo struct {
	dev_pubkey      [32]byte
	dev_privkey     [32]byte
	randomBytes     []byte
	shared_key      []byte
	clientPublicKey []byte
	PoP             string
}

// implemented the interface with algorithm curve25519
func (h *Curve25519Algo) Selector(bytesFromClient []byte) ([]byte, error) {
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
		responseBytes, err := handleSessionEnstablishment(h, []byte(decodedData))
		if err != nil {
			return nil, err
		}
		return responseBytes, nil
	} else if strings.Contains(parsedMessage[0], "S2") {
		log.Debug("Decoding client's message S2")
		responseBytes, err := handleSessionVerify(h, []byte(decodedData))
		if err != nil {
			return nil, err
		}
		return responseBytes, nil
	} else {
		log.Debug("Decoded message doesn't match with any handshake step.")
		return nil, err
	}
}

func handleSessionEnstablishment(h *Curve25519Algo, receivedMessage []byte) ([]byte, error) {
	h.PoP = "e93Y9eeQWAx00mxL6pxN3YKEyv00XjgG6V06lulibH8p7bvboo9hg9zkNivG8oWB6Qjd335Q6Bu0h9XLspQc5ak7RW6LMVG78jT0Rq49pt6fRvUt5KgaAJ5kPqyn4z4PQrw30t23Nbs15WUQ110"
	h.clientPublicKey = []byte(receivedMessage)

	err := generateKey(h)
	if err != nil {
		return nil, err
	}

	err = GenarateInitializationVector(h)
	if err != nil {
		return nil, err
	}

	generateSharedKeyWithPoP(h, h.dev_privkey[:], h.clientPublicKey[:], h.PoP)

	//concat: S1, <base64(dev_pubkey)>,<base64(dev_rand)>
	concatStr :=
		"S1," +
			base64.StdEncoding.EncodeToString(h.dev_pubkey[:]) +
			"," +
			base64.StdEncoding.EncodeToString(h.randomBytes)

	// Convert the message to a []byte
	// and put it in the variable that is exposed and called by the client in the OnRead function

	log.Debug("generated bytes for client, sessionResp0(dev_pub_key, dev_rand) ", concatStr)
	return []byte(concatStr), nil
}

func handleSessionVerify(h *Curve25519Algo, cliVerify []byte) ([]byte, error) {
	// Decrypt the token using the session key
	decryptedToken, err := decryptToken(h, cliVerify)
	if err != nil {
		log.Error("Failed to decrypt the token:", err)
		return nil, err
	}

	log.Debug("AHU pub key HEX: ", hex.EncodeToString(h.dev_pubkey[:]))
	log.Debug("cli_verify HEX: ", hex.EncodeToString(cliVerify))
	log.Debug("AHU pub key base64: ", base64.StdEncoding.EncodeToString(h.dev_pubkey[:]), " - decryptedToken from cli_verify base64: ", string(decryptedToken))
	if bytes.Equal(h.dev_pubkey[:], decryptedToken) {
		log.Debug("Token decryption successful. Confirmed the AHU public key. Generating token2 for client")
		dev_verify, err := encryptToken(h, h.clientPublicKey[:])
		if err != nil {
			log.Error("Error generating token2 for client")
			return nil, err
		}
		log.Debug("encrypted token is ", dev_verify)
		cipherTextForClient := "S3," + base64.StdEncoding.EncodeToString(dev_verify)
		log.Printf("dev_verify hex: %v", hex.EncodeToString(dev_verify))

		return []byte(cipherTextForClient), nil
	} else {
		log.Error("AHU Public Key and Decrypted AES Token contain different bytes.")
		return nil, nil
	}
}

/*
generateKey generates a public-private key pair using the Curve25519 algorithm.
*/
func generateKey(h *Curve25519Algo) error {

	_, err := io.ReadFull(rand.Reader, h.dev_privkey[:])
	if err != nil {
		return err
	}

	curve25519.ScalarBaseMult(&h.dev_pubkey, &h.dev_privkey)
	return nil
}

func generateSharedKeyWithPoP(h *Curve25519Algo, priv, pub []byte, pop string) error {

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

	h.shared_key = secret
	log.Debug("Generated Session Key HEX: ", hex.EncodeToString(secret))

	return nil
}

// Generate 32 random bytes
func GenarateInitializationVector(h *Curve25519Algo) error {
	if _, err := rand.Read(h.randomBytes); err != nil {
		log.Errorf("Error generating random bytes: %v", err)
		return err
	}
	log.Debug("encoded IV: ", hex.EncodeToString(h.randomBytes))
	return nil
}

/*
* Decrypts a []byte token using algorithm AES-256-Counter-mode (using the IV)
 */
func decryptToken(h *Curve25519Algo, cipherTextByte []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(h.shared_key)
	if err != nil {
		return nil, err
	}

	// Create a new AES-CTR mode cipher with the block
	aesctr := cipher.NewCTR(block, h.randomBytes)
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
func encryptToken(h *Curve25519Algo, plainTextByte []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(h.shared_key)
	if err != nil {
		return nil, err
	}

	// Create a new AES-CTR mode cipher with the block
	aesctr := cipher.NewCTR(block, h.randomBytes)
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
