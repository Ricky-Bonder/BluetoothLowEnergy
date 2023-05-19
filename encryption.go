package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"

	log "github.com/sirupsen/logrus"
)

var g_dev_pubkey [32]byte
var g_dev_privkey [32]byte
var g_randomBytes = make([]byte, 32)
var g_shared_key = make([]byte, 0)

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

func GenerateSharedSecretWithPoP(priv, pub, pop []byte) error {

	fmt.Printf("priv: %s, pub: %s, pop: %s\n", string(priv), string(pub), string(pop))
	var secret []byte

	secret, _ = curve25519.X25519(priv, pub)

	// Hash PoP value using SHA256
	popHash := sha256.Sum256(pop)

	// XOR shared secret with hashed PoP value
	for i := 0; i < 32; i++ {
		secret[i] ^= popHash[i]
	}

	g_shared_key = secret

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
