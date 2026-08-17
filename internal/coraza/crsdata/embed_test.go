/*
Copyright 2025 Buzz-IT GmbH.
*/

package crsdata

import (
	"testing"
)

func TestEmbedAvailable(t *testing.T) {
	if !Available() {
		t.Fatal("CRS data embed pack is empty")
	}
	if !IsKnown("scanners-user-agents.data") {
		t.Fatal("expected scanners-user-agents.data to be known")
	}
	if IsKnown("team-scanners.data") {
		t.Fatal("custom basename should not be known CRS")
	}
	m := MapFS(map[string][]byte{"team-scanners.data": []byte("evil-bot\n")})
	if _, ok := m["scanners-user-agents.data"]; !ok {
		t.Fatal("missing embedded scanners-user-agents.data")
	}
	if string(m["team-scanners.data"].Data) != "evil-bot\n" {
		t.Fatalf("override missing: %q", m["team-scanners.data"].Data)
	}
	b, err := Read("php-errors.data")
	if err != nil || len(b) == 0 {
		t.Fatalf("Read php-errors.data: %v len=%d", err, len(b))
	}
}
