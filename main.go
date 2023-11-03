package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var DevName = "en5";
var Found = false;

func main() {

	//find all network interfaces using the FindAllDevs tool;
	devices, err := pcap.FindAllDevs()
	// fmt.Println(devices)
	if err != nil {
		log.Panicln("unable to fetch network interfaces")
	}

	for _, ifDev := range devices {
			if ifDev.Name == DevName {
			Found = true
		}
	}

	if !Found {
		log.Panicln("desired device not found")
	}

	handle,err := pcap.OpenLive(DevName, 1600, false, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		log.Panicln("unable to open handle on the device")
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("port 80 and port 443"); err != nil {
		log.Panicln(err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())

	for packets := range source.Packets() {
		fmt.Println(packets)
	}
}