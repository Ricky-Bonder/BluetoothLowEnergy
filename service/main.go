package service_example

import (
	"os"

	"github.com/muka/go-bluetooth/hw"
	log "github.com/sirupsen/logrus"
)

func Run(adapterID string, mode string, hwaddr string) error {

	log.SetLevel(log.TraceLevel)

	btmgmt := hw.NewBtMgmt(adapterID)
	if len(os.Getenv("DOCKER")) > 0 {
		btmgmt.BinPath = "./bin/docker-btmgmt"
	}

	deviceName := "Ciao PIBE"
	// flag.StringVar(&deviceName, "name", "", "Name of the device to advertise")

	// flag.Parse()

	if deviceName == "" {
		log.Fatal("Device name is required")
	}

	err := serve(adapterID, deviceName)
	if err != nil {
		log.Fatalf("Failed to serve: %s", err)
	}

	// set LE mode
	btmgmt.SetPowered(false)
	btmgmt.SetLe(true)
	btmgmt.SetBredr(false)
	btmgmt.SetPowered(true)

	if mode == "client" {
		return client(adapterID, hwaddr)
	} else {
		return serve(adapterID, deviceName)
	}

}
