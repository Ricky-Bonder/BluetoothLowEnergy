package main

import (
	"time"

	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/muka/go-bluetooth/api/service"
	"github.com/muka/go-bluetooth/bluez/profile/agent"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	log "github.com/sirupsen/logrus"
)

var responseToClientBytes []byte = make([]byte, 0)
var clientPublicKey [32]byte

var PoP string = "e93Y9eeQWAx00mxL6pxN3YKEyv00XjgG6V06lulibH8p7bvboo9hg9zkNivG8oWB6Qjd335Q6Bu0h9XLspQc5ak7RW6LMVG78jT0Rq49pt6fRvUt5KgaAJ5kPqyn4z4PQrw30t23Nbs15WUQ110"

func Serve(adapterID string, deviceName string) error {

	options := service.AppOptions{
		AdapterID:  adapterID,
		AgentCaps:  agent.CapNoInputNoOutput,
		UUIDSuffix: "-0000-1000-8000-00805F9B34FB",
		UUID:       "1234",
	}

	a, err := service.NewApp(options)
	if err != nil {
		return err
	}
	defer a.Close()

	a.SetName(deviceName)

	log.Infof("HW address %s", a.Adapter().Properties.Address)

	if !a.Adapter().Properties.Powered {
		err = a.Adapter().SetPowered(true)
		if err != nil {
			log.Fatalf("Failed to power the adapter: %s", err)
		}
	}

	service1, err := a.NewService("2233")
	if err != nil {
		return err
	}

	err = a.AddService(service1)
	if err != nil {
		return err
	}

	handshakeChar, err := service1.NewChar("6677")
	if err != nil {
		return err
	}

	// define the flags for the characteristic
	handshakeChar.Properties.Flags = []string{
		gatt.FlagCharacteristicRead,
		gatt.FlagCharacteristicWrite,
	}

	// set the read callback for the handshake characteristic
	handshakeChar.OnRead(service.CharReadCallback(func(c *service.Char, options map[string]interface{}) ([]byte, error) {
		log.Warnf("GOT READ REQUEST, sending bytes: ", string(responseToClientBytes))
		return responseToClientBytes, nil
	}))

	// set the write callback for the handshake characteristic
	handshakeChar.OnWrite(service.CharWriteCallback(func(c *service.Char, bytesFromClient []byte) ([]byte, error) {
		log.Warnf("GOT WRITE REQUEST")
		var decodedData = make([]byte, len(bytesFromClient))

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
			err := decodeS0([]byte(decodedData))
			if err != nil {
				return nil, err
			}
		} else if strings.Contains(parsedMessage[0], "S2") {
			log.Debug("Decoding client's message S2")
			err := decodeS2([]byte(decodedData))
			if err != nil {
				return nil, err
			}
		} else {
			log.Debug("Decoded message doesn't match with any handshake step.")
			return nil, err
		}
		return nil, nil
	}))

	// add the characteristic to the service
	err = service1.AddChar(handshakeChar)
	if err != nil {
		return err
	}

	log.Infof("Exposed service %s", service1.Properties.UUID)
	log.Infof("Exposed Bluetooth Handshake characteristic: %s", handshakeChar.Properties.UUID)

	err = a.Run()
	if err != nil {
		return err
	}

	timeout := uint32(6 * 3600) // 6h
	log.Infof("Advertising for %ds...", timeout)
	cancel, err := a.Advertise(timeout)
	if err != nil {
		return err
	}

	defer cancel()

	wait := make(chan bool)
	go func() {
		time.Sleep(time.Duration(timeout) * time.Second)
		wait <- true
	}()

	<-wait

	return nil
}

func decodeS0(receivedMessage []byte) error {
	clientPublicKey = [32]byte(receivedMessage)

	err := GenerateKey()
	if err != nil {
		return err
	}

	err = GenarateInitializationVector()
	if err != nil {
		return err
	}

	GenerateSharedKeyWithPoP(g_dev_privkey[:], clientPublicKey[:], PoP)

	//concat: S1, <base64(dev_pubkey)>,<base64(dev_rand)>
	concatStr :=
		"S1," +
			base64.StdEncoding.EncodeToString(g_dev_pubkey[:]) +
			"," +
			base64.StdEncoding.EncodeToString(g_randomBytes)

	// Convert the message to a []byte
	// and put it in the variable that is exposed and called by the client in the OnRead function
	responseToClientBytes = []byte(concatStr)

	log.Debug("generated bytes for client, sessionResp0(dev_pub_key, dev_rand) ", concatStr)
	return nil
}

func decodeS2(cliVerify []byte) error {
	// Decrypt the token using the session key
	decryptedToken, err := DecryptToken(cliVerify)
	if err != nil {
		log.Error("Failed to decrypt the token:", err)
		return err
	}

	log.Debug("AHU pub key HEX: ", hex.EncodeToString(g_dev_pubkey[:]))
	log.Debug("cli_verify HEX: ", hex.EncodeToString(cliVerify))
	log.Debug("AHU pub key base64: ", base64.StdEncoding.EncodeToString(g_dev_pubkey[:]), " - decryptedToken from cli_verify base64: ", string(decryptedToken))
	if bytes.Equal(g_dev_pubkey[:], decryptedToken) {
		log.Debug("Token decryption successful. Confirmed the AHU public key. Generating token2 for client")
		dev_verify, err := EncryptToken(clientPublicKey[:])
		if err != nil {
			log.Error("Error generating token2 for client")
			return err
		}
		log.Debug("encrypted token is ", dev_verify)
		cipherTextForClient := "S3," + base64.StdEncoding.EncodeToString(dev_verify)
		log.Printf("dev_verify hex: %v", hex.EncodeToString(dev_verify))

		responseToClientBytes = []byte(cipherTextForClient)
	} else {
		log.Error("AHU Public Key and Decrypted AES Token contain different bytes.")
		responseToClientBytes = nil
	}

	return nil
}
