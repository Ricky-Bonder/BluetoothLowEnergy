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
func GenerateKey() (privateKey *[32]byte, publicKey *[32]byte, err error) {
	var pub, priv [32]byte

	_, err = io.ReadFull(rand.Reader, priv[:])
	if err != nil {
		return nil, nil, err
	}

	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)

	return &priv, &pub, nil
}

/*
GenerateSharedSecret generates the shared secret with a given public private key pair.
*/
func GenerateSharedSecret(priv, pub []byte) []byte {
	var secret []byte

	secret, _ = curve25519.X25519(priv, pub)

	return secret[:]

}

func GenerateKeyPair() []byte {

	privateKey := make([]byte, 32)
	_, err := rand.Read(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		log.Fatal(err)
	}

	sharedSecret, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		log.Fatal(err)
	}

	return sharedSecret
}

func ComputeSessionKey(sharedSecret []byte) (sessionKey []byte, error err) {

	bytes, _ := GenarateRandomBytes()
	pop := sha256.Sum256(bytes)
	sessionKey, err := curve25519.X25519(sharedSecret, pop[:])
	if err != nil {
		log.Errorf("Error generating scalar multiplication for Session key: %v", err)
		return nil, err
	}
	return sessionKey, nil
}

// Generate 16 random bytes
func GenarateRandomBytes() (bytes []byte, err error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		log.Errorf("Error generating random bytes: %v", err)
		return nil, err
	}
	return randomBytes, nil
}
