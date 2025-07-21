package sniffer_common

import (
	"encoding/hex"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func ParsePacket(packet gopacket.Packet) string {
	output := ""

	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		output += fmt.Sprintf("Ethernet: %s -> %s | Type: %s\n", eth.SrcMAC, eth.DstMAC, eth.EthernetType)
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		output += fmt.Sprintf("IP: %s -> %s | Protocol: %s\n", ip.SrcIP, ip.DstIP, ip.Protocol)
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		output += fmt.Sprintf("TCP: %d → %d | SYN: %t, ACK: %t\n", tcp.SrcPort, tcp.DstPort, tcp.SYN, tcp.ACK)
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		output += fmt.Sprintf("UDP: %d → %d\n", udp.SrcPort, udp.DstPort)
	}

	if app := packet.ApplicationLayer(); app != nil {
		output += fmt.Sprintf("Payload (hex): %s\n", hex.Dump(app.Payload()))
	}

	return output
}
