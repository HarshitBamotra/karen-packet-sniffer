package sniffer_server

import (
	"context"
	"fmt"
	"karen/internal/sniffer_common"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func Start(ctx context.Context, device string, filter string) {

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

	writer := pcapgo.NewWriter(f)
	err = writer.WriteFileHeader(1600, handle.LinkType())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Karen is watching")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	// for packet := range packetSource.Packets() {

	// 	writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

	// 	output := sniffer_common.ParsePacket(packet)
	// 	fmt.Println(output)
	// }

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Karen is done sniffing")
			return
		case packet, ok := <-packetChan:
			if !ok {
				fmt.Println("Packet channel closed.")
				return
			}

			writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			output := sniffer_common.ParsePacket(packet)
			fmt.Println(output)
		}
	}

}

func GetDevices() []pcap.Interface {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	return devices
}
