package anytls

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

func copyTCP(ctx context.Context, p policy.Session, in io.ReadWriteCloser, link *transport.Link, dispatcher routing.Dispatcher, dest net.Destination) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, p.Timeouts.ConnectionIdle)
	link2 := link
	if link2 == nil {
		var err error
		link2, err = dispatcher.Dispatch(ctx, dest)
		if err != nil {
			return err
		}
	}
	request := func() error {
		defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
		return buf.Copy(buf.NewReader(in), link2.Writer, buf.UpdateActivity(timer))
	}
	response := func() error {
		defer timer.SetTimeout(p.Timeouts.UplinkOnly)
		return buf.Copy(link2.Reader, buf.NewWriter(in), buf.UpdateActivity(timer))
	}
	if err := task.Run(ctx, task.OnSuccess(request, task.Close(link2.Writer)), response); err != nil && err != io.EOF {
		return errors.New("anytls: connection ends").Base(err)
	}
	return nil
}
