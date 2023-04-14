package main

import (
	"os"

	"github.com/muka/go-bluetooth/hw"
	log "github.com/sirupsen/logrus"
)

func main() {
	adapterID := "myAdapterID"
	deviceName := "AHU-Device-Name-Temp"
	err := Serve(adapterID, deviceName)
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

	// flag.StringVar(&deviceName, "name", "", "Name of the device to advertise")

	// flag.Parse()

	if deviceName == "" {
		log.Fatal("Device name is required")
	}

	err := Serve(adapterID, deviceName)
	if err != nil {
		log.Fatalf("Failed to serve: %s", err)
	}

	// set LE mode
	btmgmt.SetPowered(false)
	btmgmt.SetLe(true)
	btmgmt.SetBredr(false)
	btmgmt.SetPowered(true)

	return Serve(adapterID, deviceName)

}
