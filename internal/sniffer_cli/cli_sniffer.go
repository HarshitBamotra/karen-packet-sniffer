package sniffer_cli

import (
	"fmt"
	"karen/internal/sniffer_common"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func Start(device string, filter string) {

	fmt.Printf("Sniffing on %s with filter: %s\n", device, filter)

	handle, err := pcap.OpenLive(device, 3200, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Printf("Error setting filter: %v", err)
		}
	}

	defer handle.Close()

	f, err := os.Create("capture.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// dir, err := os.Getwd()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Printf("Logs will be saved in %s/capture.pcap\n", dir)
	// time.Sleep(3 * time.Second)

	writer := pcapgo.NewWriter(f)
	err = writer.WriteFileHeader(1600, handle.LinkType())
	if err != nil {
		log.Fatal(err)
	}

	// ctrl+c cleanup
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nKaren is done sniffing.")
		os.Exit(0)
	}()

	fmt.Println("Karen is watching")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

		output := sniffer_common.ParsePacket(packet)
		fmt.Print(output)
	}

}

func GetDevices() []pcap.Interface {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	return devices
}
