// Command state-bridge exposes the enclave's GET /state endpoint, and nothing
// else, to a browser on the operator's machine.
//
// Why this exists. The extension listens on port 7702 inside the Docker network
// the stack runs on, and that port is deliberately not published to the host
// (docker-compose.yaml). A page opened in a browser therefore has no route to
// it at all, and even with a route the extension sets no CORS header, so the
// response would be unreadable cross-origin. The web demo has one job that
// needs this endpoint: letting a judge press "try to reveal parameters" and see
// the real answer the enclave gives.
//
// What this bridge is allowed to do is the whole point:
//
//   - GET /state is the only route. Every other path and every other method is
//     refused here, so POST /action (the route that feeds work to the enclave)
//     stays unreachable from the host. A raw TCP forward would have exposed it.
//   - The upstream body is copied through byte for byte, capped. The bridge
//     never adds a field, so nothing it returns can be mistaken for enclave
//     state that the enclave did not itself report.
//   - There is no write path, no authentication to hold, and no secret in
//     reach: the enclave's answer is a model count and a version string.
//
// It runs as a container joined to the stack's network and publishes only to
// loopback (see scripts/state-bridge.sh). Stop it when the demo is over.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// maxStateBytes caps what is copied from the enclave. The real response is
// around 120 bytes; this is only here so a misconfigured upstream cannot stream
// an unbounded body into the browser.
const maxStateBytes = 8 << 10

func main() {
	listen := flag.String("listen", ":7703", "address to listen on")
	upstream := flag.String("upstream", "http://extension-tee:7702/state", "enclave state endpoint")
	flag.Parse()

	client := &http.Client{Timeout: 5 * time.Second}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Cache-Control", "no-store")

		resp, err := client.Get(*upstream)
		if err != nil {
			http.Error(w, fmt.Sprintf("reaching the enclave: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxStateBytes))
		if err != nil {
			http.Error(w, fmt.Sprintf("reading enclave response: %v", err), http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	})

	// CORS preflight is not needed for a simple GET, but answering it keeps the
	// browser console clean if the page ever adds a header.
	mux.HandleFunc("OPTIONS /state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	})

	server := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("state bridge listening on %s, forwarding GET /state to %s", *listen, *upstream)
	log.Fatal(server.ListenAndServe())
}
