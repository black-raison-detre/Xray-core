package tun

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestConfigFieldNumbers(t *testing.T) {
	fields := (&Config{}).ProtoReflect().Descriptor().Fields()
	tests := []struct {
		name protoreflect.Name
		want protoreflect.FieldNumber
	}{
		{name: "desc", want: 8},
		{name: "icmp_mode", want: 9},
	}

	for _, test := range tests {
		field := fields.ByName(test.name)
		if field == nil {
			t.Fatalf("field %q is missing", test.name)
		}
		if field.Number() != test.want {
			t.Fatalf("field %q number = %d, want %d", test.name, field.Number(), test.want)
		}
	}
}

func TestLegacyICMPModeFieldIsNotReadAsDescription(t *testing.T) {
	legacyProbe := protowire.AppendTag(nil, 8, protowire.VarintType)
	legacyProbe = protowire.AppendVarint(legacyProbe, uint64(IcmpMode_PROBE))

	config := new(Config)
	if err := proto.Unmarshal(legacyProbe, config); err != nil {
		t.Fatal(err)
	}
	if config.Desc != "" {
		t.Fatalf("legacy field 8 was decoded as Desc = %q", config.Desc)
	}
	if config.IcmpMode != IcmpMode_FAKE {
		t.Fatalf("legacy field 8 changed IcmpMode = %v, want default FAKE", config.IcmpMode)
	}
	if len(config.ProtoReflect().GetUnknown()) == 0 {
		t.Fatal("legacy field 8 was not preserved as an unknown field")
	}
}
