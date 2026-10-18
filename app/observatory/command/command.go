package command

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type service struct {
	UnimplementedObservatoryServiceServer
	ctx context.Context
	v   *core.Instance

	observatory extension.Observatory

	capabilityMu             sync.Mutex
	activeCapabilityChecks   map[string]struct{}
	capabilityDNSLookupSlots chan struct{}
}

func (s *service) GetOutboundStatus(ctx context.Context, request *GetOutboundStatusRequest) (*GetOutboundStatusResponse, error) {
	if s.observatory == nil {
		return nil, status.Error(codes.Unavailable, "observatory is not configured")
	}
	resp, err := s.observatory.GetObservation(ctx)
	if err != nil {
		return nil, err
	}
	retdata := resp.(*observatory.ObservationResult)
	return &GetOutboundStatusResponse{
		Status: retdata,
	}, nil
}

func (s *service) Register(server *grpc.Server) {
	RegisterObservatoryServiceServer(server, s)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		s := core.MustFromContext(ctx)
		sv := &service{
			ctx:                      ctx,
			v:                        s,
			capabilityDNSLookupSlots: make(chan struct{}, maxOutstandingCapabilityDNSLookups),
		}
		err := s.RequireFeatures(func(Observatory extension.Observatory) {
			sv.observatory = Observatory
		}, true)
		if err != nil {
			return nil, err
		}
		return sv, nil
	}))
}
