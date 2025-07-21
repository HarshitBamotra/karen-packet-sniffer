package main

import (
	"fmt"
	"karen/internal/api"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/start", api.HandleStartSniffing)
	http.HandleFunc("/stop", api.HandleStopSniffing)
	http.HandleFunc("/get-devices", api.HandleGetDevices)

	fmt.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
