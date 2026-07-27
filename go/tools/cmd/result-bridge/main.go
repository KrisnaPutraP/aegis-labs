// Command result-bridge exposes the extension proxy's GET /action/result/{id}
// endpoint, and nothing else, to a browser on the operator's machine.
//
// Why this exists. Settling a decision from the browser needs the signed action
// result: the 96 bytes the enclave produced plus the TEE signature over them.
// That lives off chain, behind the extension proxy, and two separate things stop
// a page from reading it directly.
//
//  1. The proxy sets no CORS header at all. The browser receives the bytes and is
//     then forbidden to read them, which is indistinguishable from a network
//     failure in page code.
//  2. The proxy is published to the internet through an ngrok free tunnel, and
//     that tunnel serves a browser User-Agent an HTML interstitial instead of the
//     JSON. The documented escape is a custom request header, which turns the
//     fetch into a preflighted request, and the tunnel answers OPTIONS on this
//     route with 405.
//
// Pointing upstream at the proxy over the stack's own Docker network settles both
// at once: no tunnel is involved, so no interstitial, and this process is free to
// add the one header the browser needs.
//
// What this bridge is allowed to do is the whole point, and it mirrors
// cmd/state-bridge deliberately:
//
//   - GET /action/result/{id} is the only route. Every other path and every other
//     method is refused here, so POST /action, the route that feeds work to the
//     enclave, stays unreachable from the host. A raw TCP forward would have
//     exposed it.
//   - The id has to look like an instruction id, 0x and 64 hex digits, before
//     anything is forwarded. That keeps a crafted path from reaching a different
//     proxy route through this one.
//   - The upstream body is copied through byte for byte, capped. The bridge never
//     adds a field, so nothing it returns can be mistaken for a result the enclave
//     did not itself sign.
//   - There is no write path and no secret in reach. What it serves is already
//     public by design: the decision is meant to be verified on chain, and the
//     signature over it is what makes relaying it trustless. The model that
//     produced the decision is not in this response and has no route out.
//
// It runs as a container joined to the stack's network and publishes only to
// loopback (see scripts/result-bridge.sh). Stop it when the demo is over.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// maxResultBytes caps what is copied from the proxy. A real action result is
// around 850 bytes; this is only here so a misconfigured upstream cannot stream
// an unbounded body into the browser.
const maxResultBytes = 64 << 10

func main() {
	listen := flag.String("listen", ":7704", "address to listen on")
	upstream := flag.String("upstream", "http://ext-proxy:6664", "extension proxy base url")
	flag.Parse()

	base := strings.TrimSuffix(*upstream, "/")
	client := &http.Client{Timeout: 10 * time.Second}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /action/result/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Cache-Control", "no-store")

		id := r.PathValue("id")
		if !isInstructionID(id) {
			http.Error(w, "not an instruction id", http.StatusBadRequest)
			return
		}

		resp, err := client.Get(base + "/action/result/" + id)
		if err != nil {
			http.Error(w, fmt.Sprintf("reaching the extension proxy: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResultBytes))
		if err != nil {
			http.Error(w, fmt.Sprintf("reading the proxy response: %v", err), http.StatusBadGateway)
			return
		}

		// The status is passed through as well. A 404 here means the enclave has
		// not published a result for that instruction yet, and the page polls on
		// it, so flattening it to 200 would break the caller.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	})

	// CORS preflight is not needed for a simple GET, but answering it keeps the
	// browser console clean if the page ever adds a header.
	mux.HandleFunc("OPTIONS /action/result/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	})

	server := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("result bridge listening on %s, forwarding GET /action/result/{id} to %s", *listen, base)
	log.Fatal(server.ListenAndServe())
}

// isInstructionID reports whether s is shaped like an instruction id: 0x followed
// by 64 hex digits. Checked before anything is forwarded, so a crafted path
// cannot be smuggled through this route to another one on the proxy.
func isInstructionID(s string) bool {
	if len(s) != 66 || !strings.HasPrefix(s, "0x") {
		return false
	}
	for _, c := range s[2:] {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}
