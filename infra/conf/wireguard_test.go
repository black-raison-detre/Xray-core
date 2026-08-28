package conf_test

import (
	"slices"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/wireguard"
)

func TestWireGuardRemoteDNS(t *testing.T) {
	want := []string{"9.9.9.9", "2620:fe::fe"}
	built, err := (&WireGuardConfig{
		IsClient:  true,
		SecretKey: "0000000000000000000000000000000000000000000000000000000000000000",
		DNS:       want,
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	got := built.(*wireguard.DeviceConfig).GetDNS()
	if !slices.Equal(got, want) {
		t.Fatalf("remote DNS = %v, want %v", got, want)
	}
}
