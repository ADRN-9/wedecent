package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const smokeGrant = "header.payload.signature"

var deviceIDPattern = regexp.MustCompile(`^wd_[a-z2-7]{16}$`)

func main() {
	listen := flag.String("listen", "127.0.0.1:17444", "loopback listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/time", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `{"unix_ms":%d}`, time.Now().UnixMilli())
	})
	mux.HandleFunc("/v1/direct-authorize/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer wdt2.") {
			http.Error(w, "invalid authorization proof", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-WeDecent-Connection-Grant") != smokeGrant {
			http.Error(w, "unexpected connection grant", http.StatusForbidden)
			return
		}
		target := strings.TrimPrefix(r.URL.Path, "/v1/direct-authorize/")
		if !deviceIDPattern.MatchString(target) {
			http.Error(w, "invalid target", http.StatusBadRequest)
			return
		}
		var body struct {
			ClientDeviceID string `json:"client_device_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !deviceIDPattern.MatchString(body.ClientDeviceID) {
			http.Error(w, "invalid client", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	log.Fatal(http.ListenAndServe(*listen, mux))
}
