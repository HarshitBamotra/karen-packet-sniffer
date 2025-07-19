package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Available Devices: ")

	for _, device := range devices {
		fmt.Println(device.Name)
	}

	handle, err := pcap.OpenLive("wlo1", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// fmt.Println(packet)
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
			fmt.Printf("Payload: %s\n", app.Payload())
		}
	}
}
