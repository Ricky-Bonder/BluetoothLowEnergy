package main

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/curve25519"

	log "github.com/sirupsen/logrus"
)

/*
GenerateKey generates a public private key pair using Curve25519.
*/
func GenerateKey(clientPublicKey *[32]byte) (privateKey *[32]byte, publicKey *[32]byte, err error) {
	var priv [32]byte

	_, err = io.ReadFull(rand.Reader, priv[:])
	if err != nil {
		return nil, nil, err
	}

	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(clientPublicKey, &priv)

	return &priv, clientPublicKey, nil
}

/*
GenerateSharedSecret generates the shared secret with a given public private key pair.
*/
func GenerateSharedSecretNoPop(priv, pub []byte) []byte {
	var secret []byte

	secret, _ = curve25519.X25519(priv, pub)

	return secret[:]

}

func GenerateSharedSecretWithPoP(priv, pub, pop []byte) ([]byte, error) {
	var secret []byte

	secret, _ = curve25519.X25519(priv, pub)

	// Hash PoP value using SHA256
	popHash := sha256.Sum256(pop)

	// XOR shared secret with hashed PoP value
	for i := 0; i < 32; i++ {
		secret[i] ^= popHash[i]
	}

	return secret[:], nil
}

// Generate 32 random bytes
func GenarateInitializationVector() (bytes []byte, err error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		log.Errorf("Error generating random bytes: %v", err)
		return nil, err
	}
	return randomBytes, nil
}
