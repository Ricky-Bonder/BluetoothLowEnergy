package main

import (
	"errors"
	"os"

	"github.com/muka/go-bluetooth/hw"
	log "github.com/sirupsen/logrus"
)

func main() {
	adapterID := "hci0"
	hostname, err := os.Hostname()
	if err != nil {
		log.Errorf("Failed to get hostname %s", err)
	}
	hostname = "RickBLETest" // @RO solo per test
	err = Run(adapterID, hostname)
	if err != nil {
		log.Fatalf("Failed to serve: %s", err)
	}
}

func Run(adapterID string, deviceName string) error {

	log.SetLevel(log.TraceLevel)

	btmgmt := hw.NewBtMgmt(adapterID)
	if len(os.Getenv("DOCKER")) > 0 {
		btmgmt.BinPath = "./bin/docker-btmgmt"
	}

	if deviceName == "" {
		log.Fatal("Device name is required")
		return errors.New("Device name is required")
	}

	err := serve(adapterID, deviceName)
	if err != nil {
		log.Fatalf("Failed to serve: %s", err)
		return err
	}

	// set LE mode
	btmgmt.SetPowered(false)
	btmgmt.SetLe(true)
	btmgmt.SetBredr(false)
	btmgmt.SetPowered(true)

	return serve(adapterID, deviceName)

}
