package api

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/anytls"
)

func TestExtractInboundUsersAnyTLS(t *testing.T) {
	want := []*protocol.User{{Email: "user@example.com"}}
	inbound := &core.InboundHandlerConfig{
		ProxySettings: serial.ToTypedMessage(&anytls.ServerConfig{Users: want}),
	}

	got := extractInboundUsers(inbound)
	if len(got) != 1 || got[0].Email != want[0].Email {
		t.Fatalf("extractInboundUsers() = %#v, want user with email %q", got, want[0].Email)
	}
}
