//go:build !routeros_gre

package conf

import (
	"strings"
	"testing"
)

func TestGREConfigUnavailableWithoutBuildTag(t *testing.T) {
	if _, err := inboundConfigLoader.LoadWithID([]byte(`{}`), "gre"); err == nil || !strings.Contains(err.Error(), "unknown config id") {
		t.Fatalf("GRE loader error = %v, want build-tag gate", err)
	}
}
