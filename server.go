package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"

	bleApiService "github.com/muka/go-bluetooth/api/service"
	"github.com/muka/go-bluetooth/bluez/profile/agent"
	"github.com/muka/go-bluetooth/bluez/profile/gatt"
	"github.com/muka/go-bluetooth/hw"
	"github.com/muka/go-bluetooth/hw/linux/btmgmt"
	log "github.com/sirupsen/logrus"
)

// type bleServer struct {
// 	appUUIDSuffix string = "-0000-1000-8000-00805F9B34FB"
// 	appUUID string = "1234"
// 	bluetoothAdapter *bleApiService.App
// 	responseToClientBytes []byte = make([]byte, 0)
// 	clientPublicKey []byte
// 	PoP string = "e93Y9eeQWAx00mxL6pxN3YKEyv00XjgG6V06lulibH8p7bvboo9hg9zkNivG8oWB6Qjd335Q6Bu0h9XLspQc5ak7RW6LMVG78jT0Rq49pt6fRvUt5KgaAJ5kPqyn4z4PQrw30t23Nbs15WUQ110"
// }

type bleServer struct {
	appUUIDSuffix         string
	appUUID               string
	bluetoothAdapter      *bleApiService.App
	responseToClientBytes []byte
	clientPublicKey       []byte
	PoP                   string
	closeBeaconFn         func()
}

func setBuetoothLowEnergyMode(btmgmt *btmgmt.BtMgmt) {
	btmgmt.SetPowered(false)
	btmgmt.SetLe(true)
	btmgmt.SetBredr(false)
	btmgmt.SetPowered(true)
}

func NewBluetoothService(adapterID string, deviceName string) (*bleServer, error) {
	b := &bleServer{
		appUUIDSuffix:         "-0000-1000-8000-00805F9B34FB",
		appUUID:               "1234",
		responseToClientBytes: make([]byte, 0),
		PoP:                   "e93Y9eeQWAx00mxL6pxN3YKEyv00XjgG6V06lulibH8p7bvboo9hg9zkNivG8oWB6Qjd335Q6Bu0h9XLspQc5ak7RW6LMVG78jT0Rq49pt6fRvUt5KgaAJ5kPqyn4z4PQrw30t23Nbs15WUQ110",
	}

	btmgmt := hw.NewBtMgmt(adapterID)
	if len(os.Getenv("DOCKER")) > 0 {
		btmgmt.BinPath = "./bin/docker-btmgmt"
	}

	if deviceName == "" {
		log.Fatal("Device name is required")
		return nil, errors.New("Device name is required")
	}

	err := b.InitializeBluetoothApp(adapterID, deviceName)
	if err != nil {
		log.Fatalf("Failed to initialize bluetooth app: %s", err)
		return nil, err
	}
	char, err := createHandshakeChar(b, "1234", "6677")
	if err != nil {
		log.Fatalf("Failed to create ble characteristic: %s", err)
		return nil, err
	}
	defineHandshakeFlagCallbacks(b, char)
	err = b.StartBeaconing(char)
	if err != nil {
		log.Fatalf("Failed to start beaconing ble characteristic: %s", err)
		return nil, err
	}
	setBuetoothLowEnergyMode(btmgmt)

	return b, nil
}

func (b *bleServer) InitializeBluetoothApp(adapterID string, deviceName string) error {

	options := bleApiService.AppOptions{
		AdapterID:  adapterID,
		AgentCaps:  agent.CapNoInputNoOutput,
		UUIDSuffix: b.appUUIDSuffix,
		UUID:       b.appUUID,
	}

	var err error
	b.bluetoothAdapter, err = bleApiService.NewApp(options)
	if err != nil {
		return err
	}

	b.bluetoothAdapter.SetName(deviceName)

	log.Infof("HW address %s", b.bluetoothAdapter.Adapter().Properties.Address)

	if !b.bluetoothAdapter.Adapter().Properties.Powered {
		err = b.bluetoothAdapter.Adapter().SetPowered(true)
		if err != nil {
			log.Fatalf("Failed to power the adapter: %s", err)
			return err
		}
	}
	return nil
}

func createService(b *bleServer, serviceUuid string) (*bleApiService.Service, error) {
	isNewService := true
	services := b.bluetoothAdapter.GetServices()

	for _, serv := range services {
		if serv.UUID == b.appUUID+serviceUuid+b.appUUIDSuffix {
			isNewService = false
			log.Warn("Bluetooth Service with UUID: ", b.appUUID+serviceUuid+b.appUUIDSuffix, " already exists.")
			return serv, nil
		}
	}

	if isNewService {
		log.Warn("Creating new Bluetooth Service with UUID: ", serviceUuid)

		service, err := b.bluetoothAdapter.NewService(serviceUuid)
		if err != nil {
			return nil, err
		}

		err = b.bluetoothAdapter.AddService(service)
		if err != nil {
			return nil, err
		}
		return service, nil
	}
	return nil, nil
}

func createCharacteristic(b *bleServer, service *bleApiService.Service, charUuid string) (*bleApiService.Char, error) {
	isNewCharacteristic := true

	characteristics := service.GetChars()
	for _, char := range characteristics {
		if char.UUID == b.appUUID+charUuid+b.appUUIDSuffix {
			isNewCharacteristic = false
			log.Warn("Bluetooth Characteristic with UUID: ", b.appUUID+charUuid+b.appUUIDSuffix, " already exists.")
			return char, nil
		}
	}

	if isNewCharacteristic {
		log.Warn("Creating new Bluetooth Characteristic with UUID: ", charUuid)
		char, err := service.NewChar(charUuid)
		if err != nil {
			return nil, err
		}
		return char, nil
	}
	return nil, nil
}

func createHandshakeChar(b *bleServer, serviceUuid string, charUuid string) (*bleApiService.Char, error) {
	service, err := createService(b, serviceUuid)
	if err != nil {
		log.Error("Error creating BLE Service. ", err)
		return nil, err
	}
	handshakeChar, err := createCharacteristic(b, service, charUuid)
	if err != nil {
		log.Error("Error creating BLE Characteristic. ", err)
		return nil, err
	}

	// add the characteristic to the service
	err = service.AddChar(handshakeChar)
	if err != nil {
		return nil, err
	}

	return handshakeChar, nil
}

func defineHandshakeFlagCallbacks(b *bleServer, handshakeChar *bleApiService.Char) {

	// define the flags for the characteristic
	handshakeChar.Properties.Flags = []string{
		gatt.FlagCharacteristicRead,
		gatt.FlagCharacteristicWrite,
	}

	// set the read callback for the handshake characteristic
	handshakeChar.OnRead(bleApiService.CharReadCallback(func(c *bleApiService.Char, options map[string]interface{}) ([]byte, error) {
		log.Warnf("GOT READ REQUEST, sending bytes: ", string(b.responseToClientBytes))
		return b.responseToClientBytes, nil
	}))

	// set the write callback for the handshake characteristic
	handshakeChar.OnWrite(bleApiService.CharWriteCallback(func(c *bleApiService.Char, bytesFromClient []byte) ([]byte, error) {
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
	}))
}

func (b *bleServer) StartBeaconing(handshakeChar *bleApiService.Char) error {

	// defer b.bluetoothAdapter.Close()

	log.Infof("Exposed Bluetooth Handshake characteristic: %s", handshakeChar.Properties.UUID)

	err := b.bluetoothAdapter.Run()
	if err != nil {
		return err
	}

	timeout := uint32(6 * 3600) // 6h
	log.Infof("Advertising for %ds...", timeout)

	b.closeBeaconFn, err = b.bluetoothAdapter.Advertise(timeout)
	if err != nil {
		return err
	}

	return nil
}

func (b *bleServer) StopBeaconing() {
	if b.closeBeaconFn != nil {
		b.closeBeaconFn()
	}
}

func handleSessionEnstablishment(b *bleServer, receivedMessage []byte) error {
	b.clientPublicKey = []byte(receivedMessage)

	err := GenerateKey()
	if err != nil {
		return err
	}

	err = GenarateInitializationVector()
	if err != nil {
		return err
	}

	GenerateSharedKeyWithPoP(g_dev_privkey[:], b.clientPublicKey[:], b.PoP)

	//concat: S1, <base64(dev_pubkey)>,<base64(dev_rand)>
	concatStr :=
		"S1," +
			base64.StdEncoding.EncodeToString(g_dev_pubkey[:]) +
			"," +
			base64.StdEncoding.EncodeToString(g_randomBytes)

	// Convert the message to a []byte
	// and put it in the variable that is exposed and called by the client in the OnRead function
	b.responseToClientBytes = []byte(concatStr)

	log.Debug("generated bytes for client, sessionResp0(dev_pub_key, dev_rand) ", concatStr)
	return nil
}

func handleSessionVerify(b *bleServer, cliVerify []byte) error {
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
		dev_verify, err := EncryptToken(b.clientPublicKey[:])
		if err != nil {
			log.Error("Error generating token2 for client")
			return err
		}
		log.Debug("encrypted token is ", dev_verify)
		cipherTextForClient := "S3," + base64.StdEncoding.EncodeToString(dev_verify)
		log.Printf("dev_verify hex: %v", hex.EncodeToString(dev_verify))

		b.responseToClientBytes = []byte(cipherTextForClient)
	} else {
		log.Error("AHU Public Key and Decrypted AES Token contain different bytes.")
		b.responseToClientBytes = nil
	}

	return nil
}
