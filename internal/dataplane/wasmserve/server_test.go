package wasmserve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/kubewaf-io/kubewaf/internal/dataplane/engine"
)

func TestLoadMultipleModules(t *testing.T) {
	dir := t.TempDir()
	corazaPath := filepath.Join(dir, "coraza.wasm")
	modsecPath := filepath.Join(dir, "modsec.wasm")
	payload := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	if err := os.WriteFile(corazaPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modsecPath, append(payload, 0x01), 0o600); err != nil {
		t.Fatal(err)
	}

	s := New(logr.Discard())
	err := s.Load(context.Background(), Options{
		Modules: []ModuleSource{
			{ID: engine.ModuleCoraza, File: corazaPath},
			{ID: engine.ModuleModSecurity, File: modsecPath},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Has(engine.ModuleCoraza) || !s.Has(engine.ModuleModSecurity) {
		t.Fatal("expected both modules")
	}

	req := httptest.NewRequest(http.MethodGet, engine.HTTPPath(engine.ModuleModSecurity), nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if rr.Header().Get("X-Wasm-Module") != string(engine.ModuleModSecurity) {
		t.Fatalf("module header=%s", rr.Header().Get("X-Wasm-Module"))
	}
	sum := sha256.Sum256(append(payload, 0x01))
	if rr.Header().Get("X-Checksum-Sha256") != hex.EncodeToString(sum[:]) {
		t.Fatal("sha mismatch")
	}
}

func TestServeUnavailableWhenEmpty(t *testing.T) {
	s := New(logr.Discard())
	req := httptest.NewRequest(http.MethodGet, engine.HTTPPath(engine.ModuleCoraza), nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestLoadFromURL(t *testing.T) {
	payload := []byte("fake-wasm-bytes")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer ts.Close()

	s := New(logr.Discard())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.LoadFromURL(ctx, engine.ModuleChallenge, ts.URL, ts.Client()); err != nil {
		t.Fatal(err)
	}
	if !s.Has(engine.ModuleChallenge) {
		t.Fatal("challenge not loaded")
	}
}

func TestPublicURLFor(t *testing.T) {
	got := PublicURLFor("kubewaf-ecds.ns.svc.cluster.local", 18002, engine.ModuleModSecurity)
	want := "http://kubewaf-ecds.ns.svc.cluster.local:18002/wasm/modsecurity-proxy-wasm.wasm"
	if got != want {
		t.Fatalf("got %s", got)
	}
}
