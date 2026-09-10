package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type ProxyServer struct {
	port   int
	server *http.Server
	errors uint64
}

type Evidence struct {
	Client                  string `json:"client"`

	// Authentication evidence.
	// These fields indicate whether an Authorization header was supplied
	// and whether this server actually enforces authentication.
	AuthenticationProvided  bool `json:"authentication_provided"`
	AuthorizationHeaderSeen bool `json:"authorization_header_seen"`
	AuthenticationEnforced  bool `json:"authentication_enforced"`

	// Request-body handling evidence.
	BodyLimitConfigured bool   `json:"body_limit_configured"`
	ReadMethod          string `json:"read_method"`

	// Resource-consumption evidence.
	Input          int    `json:"input_bytes"`
	HeapDelta      int64  `json:"heap_delta_bytes"`
	Mallocs        uint64 `json:"mallocs"`
	RSSBefore      uint64 `json:"rss_before_bytes"`
	RSSPeak        uint64 `json:"rss_peak_bytes"`
	RSSAfter       uint64 `json:"rss_after_bytes"`
	ServerDuration string `json:"server_duration"`
	ErrorsTimeouts uint64 `json:"errors_timeouts"`
}

func currentRSS() uint64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}

	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}

		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0
		}

		return kb * 1024
	}

	return 0
}

func monitorRSS(done <-chan struct{}, peak *atomic.Uint64) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rss := currentRSS()

			for {
				old := peak.Load()

				if rss <= old {
					break
				}

				if peak.CompareAndSwap(old, rss) {
					break
				}
			}

		case <-done:
			return
		}
	}
}

func (p *ProxyServer) handleRequest(
	w http.ResponseWriter,
	r *http.Request,
) {
	start := time.Now()

	// --------------------------------------------------
	// BEFORE io.ReadAll()
	// --------------------------------------------------

	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	rssBefore := currentRSS()

	var rssPeak atomic.Uint64
	rssPeak.Store(rssBefore)

	done := make(chan struct{})

	go monitorRSS(done, &rssPeak)

	// --------------------------------------------------
	// EXACT CODE PATH UNDER TEST
	// --------------------------------------------------
	//
	// No http.MaxBytesReader is used.
	// Therefore the request body is read without an
	// application-level body-size limit here.
	//

	body, err := io.ReadAll(r.Body)

	// Stop RSS monitoring immediately after ReadAll.
	close(done)

	// --------------------------------------------------
	// AFTER io.ReadAll()
	// --------------------------------------------------

	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	rssAfter := currentRSS()

	heapDelta := int64(after.Alloc) - int64(before.Alloc)

	if err != nil {
		atomic.AddUint64(&p.errors, 1)

		http.Error(
			w,
			"Error reading request body",
			http.StatusBadRequest,
		)

		return
	}

	// --------------------------------------------------
	// AUTHENTICATION EVIDENCE
	// --------------------------------------------------
	//
	// IMPORTANT:
	//
	// r.Header.Get("Authorization") != "" only tells us
	// that the client supplied an Authorization header.
	//
	// It does NOT validate the credential.
	//
	// This handler does not compare the value against a
	// token, session, API key, signature, etc.
	//
	// Therefore authentication_enforced is explicitly
	// recorded as false.
	//

	authorizationProvided := r.Header.Get("Authorization") != ""

	evidence := Evidence{
		Client: r.RemoteAddr,

		AuthenticationProvided:   authorizationProvided,
		AuthorizationHeaderSeen:  authorizationProvided,
		AuthenticationEnforced:   false,

		// No application-level request-body limit is
		// configured before io.ReadAll().
		BodyLimitConfigured: false,

		ReadMethod: "io.ReadAll(r.Body)",

		Input:          len(body),
		HeapDelta:      heapDelta,
		Mallocs:        after.Mallocs - before.Mallocs,
		RSSBefore:      rssBefore,
		RSSPeak:        rssPeak.Load(),
		RSSAfter:       rssAfter,
		ServerDuration: time.Since(start).String(),
		ErrorsTimeouts: atomic.LoadUint64(&p.errors),
	}

	// --------------------------------------------------
	// PRESERVE ORIGINAL BATCH-DETECTION BEHAVIOR
	// --------------------------------------------------

	if len(body) > 0 && body[0] == '[' {
		var batch []json.RawMessage

		if err := json.Unmarshal(body, &batch); err != nil {
			evidence.ErrorsTimeouts =
				atomic.AddUint64(&p.errors, 1)
		}
	}

	// --------------------------------------------------
	// RESPONSE
	// --------------------------------------------------

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(evidence); err != nil {
		atomic.AddUint64(&p.errors, 1)
		return
	}

	// --------------------------------------------------
	// SERVER-SIDE EVIDENCE
	// --------------------------------------------------

	fmt.Println()
	fmt.Println("==============================================")
	fmt.Println(" SERVER-SIDE EVIDENCE")
	fmt.Println("==============================================")

	fmt.Println("client:", evidence.Client)

	fmt.Printf(
		"authentication_provided=%t\n",
		evidence.AuthenticationProvided,
	)

	fmt.Printf(
		"authorization_header_seen=%t\n",
		evidence.AuthorizationHeaderSeen,
	)

	fmt.Printf(
		"authentication_enforced=%t\n",
		evidence.AuthenticationEnforced,
	)

	fmt.Printf(
		"body_limit_configured=%t\n",
		evidence.BodyLimitConfigured,
	)

	fmt.Println(
		"read_method:",
		evidence.ReadMethod,
	)

	fmt.Printf(
		"input=%d bytes (%.2f MB)\n",
		evidence.Input,
		float64(evidence.Input)/(1024*1024),
	)

	fmt.Printf(
		"heap_delta=%d bytes (%.2f MB)\n",
		evidence.HeapDelta,
		float64(evidence.HeapDelta)/(1024*1024),
	)

	fmt.Printf(
		"mallocs=%d\n",
		evidence.Mallocs,
	)

	fmt.Printf(
		"RSS_before=%d bytes (%.2f MB)\n",
		evidence.RSSBefore,
		float64(evidence.RSSBefore)/(1024*1024),
	)

	fmt.Printf(
		"RSS_peak=%d bytes (%.2f MB)\n",
		evidence.RSSPeak,
		float64(evidence.RSSPeak)/(1024*1024),
	)

	fmt.Printf(
		"RSS_after=%d bytes (%.2f MB)\n",
		evidence.RSSAfter,
		float64(evidence.RSSAfter)/(1024*1024),
	)

	fmt.Println(
		"server_duration:",
		evidence.ServerDuration,
	)

	fmt.Printf(
		"errors/timeouts=%d\n",
		evidence.ErrorsTimeouts,
	)

	fmt.Println("==============================================")
}

func NewProxyServer(port int) *ProxyServer {
	p := &ProxyServer{
		port: port,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", p.handleRequest)

	p.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,

		// Intentionally minimal for this experiment.
		//
		// No authentication enforcement.
		// No request-body size limit.
		// No ReadTimeout.
		// No ReadHeaderTimeout.
		// No WriteTimeout.
		// No IdleTimeout.
	}

	return p
}

func (p *ProxyServer) Start() error {
	log.Printf(
		"ProxyServer listening on :%d",
		p.port,
	)

	log.Println(
		"authentication: none",
	)

	log.Println(
		"authorization header: observed only; not validated",
	)

	log.Println(
		"authentication enforcement: false",
	)

	log.Println(
		"body limit: none",
	)

	log.Println(
		"read method: io.ReadAll(r.Body)",
	)

	log.Println(
		"server timeouts: none configured",
	)

	log.Println(
		"test range: 600 MB -> 1 GB",
	)

	return p.server.ListenAndServe()
}

func main() {
	port := 6080

	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			port = p
		}
	}

	p := NewProxyServer(port)

	if err := p.Start(); err != nil &&
		err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
