package main

import (
	"errors"
	"os"

	"github.com/muka/go-bluetooth/hw"
	"github.com/muka/go-bluetooth/hw/linux/btmgmt"
	log "github.com/sirupsen/logrus"
)

func main() {

	hostname, err := os.Hostname()
	if err != nil {
		log.Errorf("Failed to get hostname %s", err)
		os.Exit(1)
	}
	hostname = "AHU-PowerFlow"
	err = Run(hostname)
	if err != nil {
		log.Fatalf("Failed to serve: %s", err)
		os.Exit(2)
	}
}

func Run(deviceName string) error {
	const adapterID = "hci0"

	log.SetLevel(log.TraceLevel)

	btmgmt := hw.NewBtMgmt(adapterID)
	if len(os.Getenv("DOCKER")) > 0 {
		btmgmt.BinPath = "./bin/docker-btmgmt"
	}

	if deviceName == "" {
		log.Fatal("Device name is required")
		return errors.New("Device name is required")
	}

	err := Serve(adapterID, deviceName)
	if err != nil {
		log.Fatalf("Failed to serve: %s", err)
		return err
	}

	setBuetoothLowEnergyMode(btmgmt)

	return Serve(adapterID, deviceName)

}

func setBuetoothLowEnergyMode(btmgmt *btmgmt.BtMgmt) {
	btmgmt.SetPowered(false)
	btmgmt.SetLe(true)
	btmgmt.SetBredr(false)
	btmgmt.SetPowered(true)
}
