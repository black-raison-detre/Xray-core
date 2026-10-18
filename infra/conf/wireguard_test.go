package conf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/proxy/wireguard"
	"google.golang.org/protobuf/proto"
)

func TestWireGuardDomainStrategyOptionalCompatibility(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    *wireguard.DeviceConfig_DomainStrategy
		wantErr bool
	}{
		{name: "omitted keeps upstream defaults"},
		{name: "force ip preserves explicit zero", value: "ForceIP", want: enumPointer(wireguard.DeviceConfig_FORCE_IP)},
		{name: "force ipv4", value: " FORCEIPv4 ", want: enumPointer(wireguard.DeviceConfig_FORCE_IP4)},
		{name: "force ipv6", value: "ForceIPv6", want: enumPointer(wireguard.DeviceConfig_FORCE_IP6)},
		{name: "force ipv4 then ipv6", value: "ForceIPv4v6", want: enumPointer(wireguard.DeviceConfig_FORCE_IP46)},
		{name: "force ipv6 then ipv4", value: "ForceIPv6v4", want: enumPointer(wireguard.DeviceConfig_FORCE_IP64)},
		{name: "unsupported", value: "AsIs", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message, err := (&WireGuardConfig{
				IsClient:       true,
				SecretKey:      strings.Repeat("A", 43),
				DomainStrategy: test.value,
			}).Build()
			if test.wantErr {
				if err == nil {
					t.Fatal("Build() succeeded for unsupported domainStrategy")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			config := message.(*wireguard.DeviceConfig)
			if test.want == nil {
				if config.DomainStrategy != nil {
					t.Fatalf("DomainStrategy = %v, want unset", *config.DomainStrategy)
				}
				return
			}
			if config.DomainStrategy == nil || *config.DomainStrategy != *test.want {
				t.Fatalf("DomainStrategy = %v, want %v", config.DomainStrategy, *test.want)
			}

			encoded, err := proto.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			var decoded wireguard.DeviceConfig
			if err := proto.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.DomainStrategy == nil || *decoded.DomainStrategy != *test.want {
				t.Fatalf("round-tripped DomainStrategy = %v, want %v", decoded.DomainStrategy, *test.want)
			}
		})
	}
}

func TestWireGuardDomainStrategyJSONCompatibility(t *testing.T) {
	settings := json.RawMessage(`{"secretKey":"` + strings.Repeat("A", 43) + `","domainStrategy":"ForceIPv6v4"}`)
	config, err := outboundConfigLoader.LoadWithID(settings, "wireguard")
	if err != nil {
		t.Fatal(err)
	}
	built, err := config.(Buildable).Build()
	if err != nil {
		t.Fatal(err)
	}
	got := built.(*wireguard.DeviceConfig).DomainStrategy
	if got == nil || *got != wireguard.DeviceConfig_FORCE_IP64 {
		t.Fatalf("JSON domainStrategy = %v, want FORCE_IP64", got)
	}
}

func enumPointer(value wireguard.DeviceConfig_DomainStrategy) *wireguard.DeviceConfig_DomainStrategy {
	return &value
}
