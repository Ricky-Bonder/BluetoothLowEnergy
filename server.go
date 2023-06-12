package main

import (
	"errors"
	"os"

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

type BleServer struct {
	appUUIDSuffix         string
	appUUID               string
	bluetoothAdapter      *bleApiService.App
	responseToClientBytes []byte
	closeBeaconFn         func()
	payloadHandler        IHandshake
}

func setBuetoothLowEnergyMode(btmgmt *btmgmt.BtMgmt) {
	btmgmt.SetPowered(false)
	btmgmt.SetLe(true)
	btmgmt.SetBredr(false)
	btmgmt.SetPowered(true)
}

func NewBluetoothService(adapterID string, deviceName string, encryptionHandler IHandshake) (*BleServer, error) {
	b := &BleServer{
		appUUIDSuffix:         "-0000-1000-8000-00805F9B34FB",
		appUUID:               "1234",
		responseToClientBytes: make([]byte, 0),
		payloadHandler:        encryptionHandler,
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
	char, err := createServiceWithChar(b, "1234", "6677")
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

func (b *BleServer) InitializeBluetoothApp(adapterID string, deviceName string) error {

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

func getService(b *BleServer, serviceUuid string) *bleApiService.Service {
	services := b.bluetoothAdapter.GetServices()

	for _, serv := range services {
		if serv.UUID == b.appUUID+serviceUuid+b.appUUIDSuffix {
			log.Info("Bluetooth Service with UUID: ", b.appUUID+serviceUuid+b.appUUIDSuffix, " was found.")
			return serv
		}
	}
	return nil
}

func createService(b *BleServer, serviceUuid string) (*bleApiService.Service, error) {
	retrievedService := getService(b, serviceUuid)

	if retrievedService == nil {
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
	return retrievedService, nil
}

func getCharacteristic(b *BleServer, service *bleApiService.Service, charUuid string) *bleApiService.Char {
	characteristics := service.GetChars()

	for _, char := range characteristics {
		if char.UUID == b.appUUID+charUuid+b.appUUIDSuffix {
			log.Info("Bluetooth Characteristic with UUID: ", b.appUUID+charUuid+b.appUUIDSuffix, " was found.")
			return char
		}
	}
	return nil
}

func createCharacteristic(b *BleServer, service *bleApiService.Service, charUuid string) (*bleApiService.Char, error) {
	retrievedCharacteristic := getCharacteristic(b, service, charUuid)

	if retrievedCharacteristic == nil {
		log.Warn("Creating new Bluetooth Characteristic with UUID: ", charUuid)
		char, err := service.NewChar(charUuid)
		if err != nil {
			return nil, err
		}
		return char, nil
	}
	return retrievedCharacteristic, nil
}

func createServiceWithChar(b *BleServer, serviceUuid string, charUuid string) (*bleApiService.Char, error) {
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

func defineHandshakeFlagCallbacks(b *BleServer, handshakeChar *bleApiService.Char) {

	// define the flags for the characteristic
	handshakeChar.Properties.Flags = []string{
		gatt.FlagCharacteristicRead,
		gatt.FlagCharacteristicWrite,
	}

	// set the read callback for the handshake characteristic
	handshakeChar.OnRead(bleApiService.CharReadCallback(func(c *bleApiService.Char, options map[string]interface{}) ([]byte, error) {
		log.Warnf("GOT READ REQUEST, sending bytes: %s", string(b.responseToClientBytes))
		return b.responseToClientBytes, nil
	}))

	// set the write callback for the handshake characteristic
	handshakeChar.OnWrite(bleApiService.CharWriteCallback(func(c *bleApiService.Char, bytesFromClient []byte) ([]byte, error) {
		log.Warnf("GOT WRITE REQUEST")
		// var decodedData = make([]byte, len(bytesFromClient))

		var err error
		b.responseToClientBytes, err = b.payloadHandler.Selector(bytesFromClient)
		if err != nil {
			log.Error(err)
		}

		return nil, nil
	}))
}

func (b *BleServer) StartBeaconing(handshakeChar *bleApiService.Char) error {

	// defer b.bluetoothAdapter.Close()

	log.Infof("Exposed Bluetooth Handshake characteristic: %s", handshakeChar.Properties.UUID)

	err := b.bluetoothAdapter.Run()
	if err != nil {
		return err
	}

	timeout := uint32(6 * 3600) // 6h
	log.Infof("Advertising for %ds...", timeout)

	b.closeBeaconFn, err = b.bluetoothAdapter.Advertise(0)
	if err != nil {
		return err
	}

	return nil
}

func (b *BleServer) StopBeaconing() {
	if b.closeBeaconFn != nil {
		b.closeBeaconFn()
	}
}
