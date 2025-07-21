package api

import (
	"context"
	"encoding/json"
	"karen/internal/sniffer_server"
	"net/http"
)

var cancelFunc context.CancelFunc

type SniffRequest struct {
	Device string `json:"device"`
	Filter string `json:"filter"`
}

func HandleStartSniffing(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SniffRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if cancelFunc != nil {
		w.Write([]byte("Sniffer already running"))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancelFunc = cancel

	go sniffer_server.Start(ctx, req.Device, req.Filter)

	w.Write([]byte("Started sniffing"))
}

func HandleStopSniffing(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	if cancelFunc != nil {
		cancelFunc()
		cancelFunc = nil
		w.Write([]byte("Sniffer stopped"))
	} else {
		w.Write([]byte("No sniffer running"))
	}
}

func HandleGetDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
		return
	}

	devices := sniffer_server.GetDevices()

	var names []string

	for _, device := range devices {
		names = append(names, device.Name)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(names)
}
