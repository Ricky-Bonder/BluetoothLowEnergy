package main

import (
	"time"

	"encoding/base64"

	"github.com/muka/go-bluetooth/api/service"
	"github.com/muka/go-bluetooth/bluez/profile/agent"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	log "github.com/sirupsen/logrus"
)

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
	}

	// set the read and write callbacks for the characteristic
	handshakeChar.OnRead(service.CharReadCallback(func(c *service.Char, options map[string]interface{}) ([]byte, error) {
		log.Warnf("GOT READ REQUEST")
		return []byte{42}, nil
	}))

	handshakeChar.OnWrite(service.CharWriteCallback(func(c *service.Char, value []byte) ([]byte, error) {
		log.Warnf("GOT WRITE REQUEST")
		// Decode the encoded key using base64 decoding
		decodedKey, err := base64.StdEncoding.DecodeString(string(value))
		if err != nil {
			log.Errorf("Error decoding key: %v", err)
			return nil, err
		}

		log.Infof("decoded key: %s ", string(decodedKey))

		var clientPublicKey [32]byte
		copy(clientPublicKey[:], decodedKey)

		// Use the decoded key to generate the shared key
		// sharedKey, err := generateSharedKey(decodedKey)
		// if err != nil {
		// 	log.Errorf("Error generating shared key: %v", err)
		// 	return nil, err
		// }

		// // Store the shared key in the server's state
		// serverState.sharedKey = sharedKey

		_, publicKey, err := GenerateKey(&clientPublicKey)
		if err != nil {
			return nil, err
		}

		IV, err := GenarateInitializationVector()
		if err != nil {
			return nil, err
		}

		//concat: S1, <base64(chiave pubblica)>,<base64(random)>
		concatStr := "S1," + base64.RawStdEncoding.EncodeToString(publicKey[:]) + "," + base64.RawStdEncoding.EncodeToString(IV)

		// Convert the public key to a []byte
		keyBytes := []byte(concatStr)

		// send response to client

		err = c.WriteValue(keyBytes, nil)
		if err != nil {
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
