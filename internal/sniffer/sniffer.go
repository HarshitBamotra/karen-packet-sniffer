package sniffer

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Logs will be saved in %s/capture.pcap\n", dir)
	time.Sleep(3 * time.Second)

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
		// fmt.Println(packet)
		writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

		fmt.Println()

		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth := ethLayer.(*layers.Ethernet)
			fmt.Printf("Ethernet: %s -> %s | Type: %s\n", eth.SrcMAC, eth.DstMAC, eth.EthernetType)
		}

		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip := ipLayer.(*layers.IPv4)
			fmt.Printf("IP: %s -> %s | Protocol: %s\n", ip.SrcIP, ip.DstIP, ip.Protocol)
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			fmt.Printf("TCP: %d → %d | SYN: %t, ACK: %t\n", tcp.SrcPort, tcp.DstPort, tcp.SYN, tcp.ACK)
		}

		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			fmt.Printf("UDP: %d → %d\n", udp.SrcPort, udp.DstPort)
		}

		if app := packet.ApplicationLayer(); app != nil {
			fmt.Printf("Payload (hex): %s\n", hex.Dump(app.Payload()))
		}
	}

}
