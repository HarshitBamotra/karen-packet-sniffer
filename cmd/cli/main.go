package main

import (
	"karen/internal/sniffer"
	"log"

	"github.com/google/gopacket/pcap"
	"github.com/manifoldco/promptui"
)

func main() {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	if len(devices) == 0 {
		log.Fatal("No devices found")
	}

	prompt := promptui.Select{
		Label: "Select",
		Items: devices,
		Templates: &promptui.SelectTemplates{
			Label:    "{{ . }}",
			Active:   "▶ {{ .Name | cyan }} ({{ .Description | faint }})",
			Inactive: "  {{ .Name }} ({{ .Description }})",
			Selected: "✔ Using {{ .Name | green }}",
		},
		Size: 10,
	}

	idx, _, err := prompt.Run()
	if err != nil {
		log.Fatal(err)
	}
	iface := devices[idx].Name

	filterPrompt := promptui.Prompt{
		Label:   "Enter BPF FIlter (leave blank for none)",
		Default: "",
	}

	filter, err := filterPrompt.Run()
	if err != nil {
		log.Fatal(err)
	}

	sniffer.Start(iface, filter)

	// iface := flag.String("iface", "", "Interface to sniff on")
	// filter := flag.String("filter", "", "BPF FIlter")
	// flag.Parse()

	// if *iface == "" {
	// 	log.Fatal("Please provide a network interface using --iface")
	// }

	// sniffer.Start(*iface, *filter)
}
