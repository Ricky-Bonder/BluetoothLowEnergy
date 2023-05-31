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

func serve(adapterID string, deviceName string) error {

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

		//		gatt.FlagCharacteristicNotify,
	}

	// set the read and write callbacks for the characteristic
	handshakeChar.OnRead(service.CharReadCallback(func(c *service.Char, options map[string]interface{}) ([]byte, error) {
		log.Warnf("GOT READ REQUEST, sending bytes: ", string(responseToClientBytes))
		// log.Warnf("GOT READ REQUEST, sending bytes: ", string(responseToClientBytes), "raw: ", responseToClientBytes, "encoded base64:", base64.StdEncoding.EncodeToString(responseToClientBytes))
		return responseToClientBytes, nil
	}))

	handshakeChar.OnWrite(service.CharWriteCallback(func(c *service.Char, value []byte) ([]byte, error) {
		log.Warnf("GOT WRITE REQUEST")
		var decodedData = make([]byte, len(value))

		parsedMessage := strings.SplitN(string(value), ",", 2)
		log.Info("base64 body of message is ", parsedMessage[1])

		// Decode the encoded key using base64 decoding
		log.Debug("len of data received: ", len(decodedData), " - string value received: ", string(value))
		decodedData, err := base64.StdEncoding.DecodeString(parsedMessage[1])
		if err != nil {
			log.Errorf("Error: %v Decoding: %s ", err, string(value))
			return nil, err
		}

		log.Infof("decoded data as string: %v ", decodedData)

		if strings.Contains(parsedMessage[0], "S0") {
			log.Debug("Decoding client's message S0")
			return decodeS0([]byte(decodedData))
		} else if strings.Contains(parsedMessage[0], "S2") {
			log.Debug("Decoding client's message S2")
			return decodeS2([]byte(decodedData))
		} else {
			return nil, err
		}
	}))

	// add the characteristic to the service
	err = service1.AddChar(handshakeChar)
	if err != nil {
		return err
	}

	log.Infof("Exposed service %s", service1.Properties.UUID)
	log.Infof("Exposed characteristic: %s", handshakeChar.Properties.UUID)

	// descr1, err := handshakeChar.NewDescr("4455")
	// if err != nil {
	// 	return err
	// }

	// descr1.Properties.Flags = []string{
	// 	gatt.FlagDescriptorRead,
	// 	gatt.FlagDescriptorWrite,
	// }

	// descr1.OnRead(service.DescrReadCallback(func(c *service.Descr, options map[string]interface{}) ([]byte, error) {
	// 	log.Warnf("GOT READ REQUEST")
	// 	return []byte{42}, nil
	// }))
	// descr1.OnWrite(service.DescrWriteCallback(func(d *service.Descr, value []byte) ([]byte, error) {
	// 	log.Warnf("GOT WRITE REQUEST")
	// 	return value, nil
	// }))

	// err = handshakeChar.AddDescr(descr1)
	// if err != nil {
	// 	return err
	// }

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

func decodeS0(receivedMessage []byte) ([]byte, error) {
	clientPublicKey = [32]byte(receivedMessage)

	err := GenerateKey()
	if err != nil {
		return nil, err
	}

	err = GenarateInitializationVector()
	if err != nil {
		return nil, err
	}

	GenerateSharedSecretWithPoP(g_dev_privkey[:], clientPublicKey[:], PoP)

	//concat: S1, <base64(chiave pubblica)>,<base64(random)>
	concatStr :=
		"S1," +
			base64.StdEncoding.EncodeToString(g_dev_pubkey[:]) +
			"," +
			base64.StdEncoding.EncodeToString(g_randomBytes)

	// Convert the public key to a []byte
	responseToClientBytes = []byte(concatStr)

	// send response to client
	log.Debug("generated bytes for client, sessionResp0(dev_pub_key, dev_rand) ", concatStr)
	return responseToClientBytes, nil
}

func decodeS2(cliVerify []byte) ([]byte, error) {
	log.Debug("@@@ bytes:", string(cliVerify))

	// Decrypt the token using the session key
	decryptedToken, err := decryptToken(cliVerify)
	if err != nil {
		log.Error("Failed to decrypt the token:", err)
		return nil, err
	}

	log.Debug("AHU pub key: ", hex.EncodeToString(g_dev_pubkey[:]))
	log.Debug("cliVerify: ", hex.EncodeToString(cliVerify))
	// log.Debug("AHU pub key: ", base64.StdEncoding.EncodeToString(g_dev_pubkey[:]), " - cliVerify: ", base64.StdEncoding.EncodeToString(cliVerify))
	log.Debug("AHU pub key: ", base64.StdEncoding.EncodeToString(g_dev_pubkey[:]), " - decryptedToken: ", string(decryptedToken))
	if bytes.Equal(g_dev_pubkey[:], decryptedToken) {
		log.Debug("Token decryption successful. Confirmed the AHU public key. Generating token2 for client")
		token2, err := encryptToken2(g_dev_pubkey[:])
		if err != nil {
			log.Error("Error generating token2 for client")
			return nil, err
		}
		log.Debug("token2 is ", token2)
		responseToClientBytes = []byte(token2)
	} else {
		log.Error("AHU Public Key and Decrypted AES Token contain different bytes.")
		responseToClientBytes = nil
	}

	return decryptedToken, nil
}
