package main

import (
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

func main() {

	hostname, err := os.Hostname()
	if err != nil {
		log.Errorf("Failed to get hostname %s", err)
		os.Exit(1)
	}
	const adapterID = "hci0"
	hostname = "AHU-PowerFlow"
	var myEncryptionAlgorithm IHandshake = &Curve25519Algo{}
	bleService, err := NewBluetoothService(adapterID, hostname, myEncryptionAlgorithm)
	if err != nil {
		log.Fatalf("Failed to serve: %s", err)
		os.Exit(2)
	}
	fmt.Println(bleService)

	time.Sleep(time.Duration(6) * time.Hour)
	bleService.StopBeaconing()
}
