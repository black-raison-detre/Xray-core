//go:build routeros_gre

package gre

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/features/extension"
	"google.golang.org/protobuf/proto"
)

type testObservatory struct {
	report proto.Message
	err    error
}

func (*testObservatory) Type() interface{} { return extension.ObservatoryType() }
func (*testObservatory) Start() error      { return nil }
func (*testObservatory) Close() error      { return nil }
func (o *testObservatory) GetObservation(context.Context) (proto.Message, error) {
	return o.report, o.err
}

func TestHandlerICMPEchoDelay(t *testing.T) {
	handler := &Handler{ctx: context.Background(), config: &Config{IcmpMode: IcmpMode_PROBE}, observatory: &testObservatory{
		report: &observatory.ObservationResult{Status: []*observatory.OutboundStatus{
			{OutboundTag: "dead", Alive: false, Delay: 1},
			{OutboundTag: "slow", Alive: true, Delay: 80},
			{OutboundTag: "fast", Alive: true, Delay: 35},
		}},
	}}
	delay, ok := handler.icmpEchoDelay()
	if !ok || delay != 35*time.Millisecond {
		t.Fatalf("icmpEchoDelay() = (%s, %v)", delay, ok)
	}
	handler.observatory = &testObservatory{report: &observatory.ObservationResult{}}
	if _, ok := handler.icmpEchoDelay(); ok {
		t.Fatal("probe mode accepted an empty observation")
	}
	handler.config.IcmpMode = IcmpMode_FAKE
	if delay, ok := handler.icmpEchoDelay(); !ok || delay != 0 {
		t.Fatalf("fake icmpEchoDelay() = (%s, %v)", delay, ok)
	}
}
