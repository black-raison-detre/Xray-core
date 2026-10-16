package mux_test

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
)

func TestPacketReaderWithoutUDPSource(t *testing.T) {
	for name, dest := range map[string]*net.Destination{
		"nil": nil,
		"tcp": {Network: net.Network_TCP},
	} {
		t.Run(name, func(t *testing.T) {
			r := mux.NewPacketReader(bytes.NewReader([]byte{0, 1, 'x'}), dest)
			mb, err := r.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			defer buf.ReleaseMulti(mb)
			if len(mb) != 1 || mb[0].String() != "x" || mb[0].UDP != nil {
				t.Fatalf("expected payload x without a UDP source, got %v", mb)
			}
		})
	}
}
