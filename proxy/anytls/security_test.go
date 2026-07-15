package anytls

import (
	"testing"

	"github.com/xtls/xray-core/transport/internet"
)

func TestRequiredStreamSecurity(t *testing.T) {
	for _, test := range []struct {
		name     string
		security string
		want     bool
	}{
		{name: "TLS", security: tlsSecurityType, want: true},
		{name: "REALITY", security: realitySecurityType, want: true},
		{name: "none"},
		{name: "other", security: "example.Security"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := hasRequiredStreamSecurity(&internet.MemoryStreamConfig{SecurityType: test.security})
			if got != test.want {
				t.Fatalf("hasRequiredStreamSecurity() = %v, want %v", got, test.want)
			}
		})
	}
}
