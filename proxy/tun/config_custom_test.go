package tun

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestCustomICMPConfigPreservesUpstreamFields(t *testing.T) {
	want := &Config{Desc: "Xray-GUI TUN", AutoSystemDnsToGateway: true, AutoSystemWfpBlockLeak: []string{"dns"}, IcmpMode: IcmpMode_PROBE}
	data, err := proto.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got := new(Config)
	if err := proto.Unmarshal(data, got); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(want, got) {
		t.Fatalf("config round trip: %v", got)
	}
	fields := got.ProtoReflect().Descriptor().Fields()
	if fields.ByName("icmp_mode").Number() != 11 || fields.ByName("auto_system_dns_to_gateway").Number() != 9 || fields.ByName("auto_system_wfp_block_leak").Number() != 10 {
		t.Fatal("private ICMP field collides with upstream configuration")
	}
}
