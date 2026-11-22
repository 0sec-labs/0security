package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
)

type event struct {
	Type    string `json:"type"`
	OrderID int64  `json:"orderId"`
}

func health(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}

func receive(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil || !validSignature(body, r.Header.Get("X-Signature")) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var e event
	if json.Unmarshal(body, &e) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	log.Printf("event %s for order %d", e.Type, e.OrderID)
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", health)
	mux.HandleFunc("/events", receive)
	log.Fatal(http.ListenAndServe(":8081", mux))
}
