# Karen: Packet Sniffer

## Overview

Karen is a lightweight packet sniffer written in Go, designed to help you inspect network traffic directly from your terminal. It's fast, interactive, and easy to use ideal for learning, debugging, or monitoring packets in real-time.

---

## Features

- Lists all available network interfaces
- Arrow-key selection of interface via interactive CLI
- Custom packet filter input (e.g. `tcp`, `udp`, `port 80`, etc.)
- Captures and logs packet data using [gopacket](https://github.com/google/gopacket)
- Outputs to `capture.pcap` for use with Wireshark or analysis tools

---

## Installation

Make sure you have Go installed. You can download it from [https://golang.org/dl](https://golang.org/dl).

```bash
git clone https://github.com/HarshitBamotra/karen-packet-sniffer.git
cd karen-packet-sniffer
go mod tidy
```
---

## Usage

**You need sudo privileges to run Karen**

#### To run Karen:
```bash
sudo go run cmd/cli/main.go
```

#### Or you can use the helper script
##### 1. Add executable permissions
```bash
chmod +x start.sh
```
##### 2. Now you can run Karen with script
```bash
./start.sh
```
---

## How it works
1. Lists all network devices on your system.
2. Lets you choose one using arrow keys.
3. Prompts you to set a capture filter (can be empty for all traffic).
4. Begins sniffing and printing basic packet info.
5. Writes full packet data to capture.pcap.

---

## Planned Features

1. Live packet filtering & search
2. eBPF-based traffic filtering
3. Protocol breakdown & statistics
4. WebSocket or Web UI display
5. Packet replay