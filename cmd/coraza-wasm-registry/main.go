package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

func BuildToWASM(sourceDir, outputWASM string) error {
	// sourceDir = "." or path to the package you want to build
	cmd := exec.Command("go", "run",
		"mage.go",
	)

	// Set the WASM target
	cmd.Env = append(os.Environ(),
		"GOOS=wasip1", // classic browser WASM
		"GOARCH=wasm",
	)

	// Optional: build in the correct directory
	cmd.Dir = sourceDir

	// Capture output for debugging
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wasm build failed: %w\noutput: %s", err, output)
	}

	fmt.Printf("✅ Successfully built WASM: %s\n", outputWASM)
	return nil
}

func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next(w, r)
		log.Printf("%s %s - %s", r.Method, r.URL.Path, time.Since(start))
	}
}
func healthHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Message: "API is healthy ✅",
	})
}
func respondJSON(w http.ResponseWriter, status int, payload interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(payload)
}

func respondData(w http.ResponseWriter, status int, payload []byte) (int, error) {
	//w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return w.Write(payload)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, APIError{
		Success: false,
		Error:   message,
		Code:    status,
	})
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

type APIError struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	Code    int    `json:"code"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "client" {
		runClient()
		return
	}

	// Server mode
	mux := http.NewServeMux()

	// Health & info
	mux.HandleFunc("GET /health", loggingMiddleware(healthHandler))

	// API v1 routes
	mux.HandleFunc("GET /api/v1beta1/coraza/", loggingMiddleware(getCorazaHandler))
	mux.HandleFunc("POST /api/v1beta1/coraza", loggingMiddleware(createCorazaHandler))
	// mux.HandleFunc("DELETE /api/v1/items/", loggingMiddleware(deleteCorazaHandler))

	// Optional: simple root
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, APIResponse{
			Success: true,
			Message: "Welcome to the Go REST API! Try /health or /api/v1/coraza",
		})
	})

	server := &http.Server{
		Addr:    ":3000",
		Handler: mux,
	}

	// Start server
	go func() {
		log.Printf("🚀 API server running on http://localhost:3000")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}

	log.Println("✅ Server stopped gracefully")
}

func runClient() {
	// Support running as `binary client [flags...]`
	if len(os.Args) > 1 && os.Args[1] == "client" {
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
	}

	url := flag.String("url", "http://localhost:3000", "Registry base URL")
	name := flag.String("name", "test", "Name of the WASM module")
	output := flag.String("output", "coraza.wasm", "Output WASM file path")
	create := flag.Bool("create", false, "Trigger create/build before downloading")
	flag.Parse()

	fmt.Println("Simple Coraza WASM Registry Client")
	fmt.Printf("URL: %s, Name: %s, Create: %v, Output: %s\n", *url, *name, *create, *output)

	if *create {
		createURL := *url + "/api/v1beta1/coraza"
		input := CreateCoraza{
			Name: *name,
		}
		body, err := json.Marshal(input)
		if err != nil {
			log.Fatal(err)
		}
		resp, err := http.Post(createURL, "application/json", bytes.NewBuffer(body))
		if err != nil {
			log.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode >= 400 {
			b, _ := io.ReadAll(resp.Body)
			log.Fatalf("Create failed with status %d: %s", resp.StatusCode, string(b))
		}
		fmt.Println("✅ Successfully triggered build for", *name)
	}

	// Download the WASM
	getURL := *url + "/api/v1beta1/coraza/" + *name
	resp, err := http.Get(getURL)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		log.Fatalf("Download failed with status %d: %s", resp.StatusCode, string(b))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(*output, data, 0644); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✅ Successfully saved WASM to %s (%d bytes)\n", *output, len(data))
}
