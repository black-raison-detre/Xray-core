package command

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/egress"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"google.golang.org/grpc"
)

// routingServer is an implementation of RoutingService.
type routingServer struct {
	router       routing.Router
	routingStats stats.Channel
}

func (s *routingServer) GetBalancerInfo(ctx context.Context, request *GetBalancerInfoRequest) (*GetBalancerInfoResponse, error) {
	var ret GetBalancerInfoResponse
	ret.Balancer = &BalancerMsg{}
	if bo, ok := s.router.(routing.BalancerOverrider); ok {
		{
			res, err := bo.GetOverrideTarget(request.GetTag())
			if err != nil {
				return nil, err
			}
			ret.Balancer.Override = &OverrideInfo{
				Target: res,
			}
		}
	}

	if pt, ok := s.router.(routing.BalancerPrincipleTarget); ok {
		{
			res, err := pt.GetPrincipleTarget(request.GetTag())
			if err != nil {
				errors.LogInfoInner(ctx, err, "unable to obtain principle target")
			} else {
				ret.Balancer.PrincipleTarget = &PrincipleTargetInfo{Tag: res}
			}
		}
	}
	return &ret, nil
}

func (s *routingServer) OverrideBalancerTarget(ctx context.Context, request *OverrideBalancerTargetRequest) (*OverrideBalancerTargetResponse, error) {
	if bo, ok := s.router.(routing.BalancerOverrider); ok {
		return &OverrideBalancerTargetResponse{}, bo.SetOverrideTarget(request.BalancerTag, request.Target)
	}
	return nil, errors.New("unsupported router implementation")
}

func (s *routingServer) AddRule(ctx context.Context, request *AddRuleRequest) (*AddRuleResponse, error) {
	if bo, ok := s.router.(routing.Router); ok {
		return &AddRuleResponse{}, bo.AddRule(request.Config, request.ShouldAppend)
	}
	return nil, errors.New("unsupported router implementation")
}

func (s *routingServer) RemoveRule(ctx context.Context, request *RemoveRuleRequest) (*RemoveRuleResponse, error) {
	if bo, ok := s.router.(routing.Router); ok {
		return &RemoveRuleResponse{}, bo.RemoveRule(request.RuleTag)
	}
	return nil, errors.New("unsupported router implementation")
}

func (s *routingServer) ListRule(ctx context.Context, request *ListRuleRequest) (*ListRuleResponse, error) {
	if bo, ok := s.router.(routing.Router); ok {
		response := &ListRuleResponse{}
		for _, v := range bo.ListRule() {
			response.Rules = append(response.Rules, &ListRuleItem{
				Tag:     v.GetOutboundTag(),
				RuleTag: v.GetRuleTag(),
			})
		}
		return response, nil
	}
	return nil, errors.New("unsupported router implementation")
}

func (s *routingServer) GetEgressStatus(ctx context.Context, request *GetEgressStatusRequest) (*GetEgressStatusResponse, error) {
	if request == nil {
		request = &GetEgressStatusRequest{}
	}
	snapshot := egress.Status(ctx, egress.Request{
		Preview:            request.Preview,
		Refresh:            request.Refresh,
		InterfaceName:      request.InterfaceName,
		ExcludedInterfaces: request.ExcludedInterfaces,
	})
	response := &GetEgressStatusResponse{
		State:               snapshot.State,
		Mode:                snapshot.Mode,
		ConfiguredInterface: snapshot.ConfiguredInterface,
		Generation:          snapshot.Generation,
		Ipv4:                egressFamilyMessage(snapshot.IPv4),
		Ipv6:                egressFamilyMessage(snapshot.IPv6),
		Candidates:          make([]*EgressCandidate, 0, len(snapshot.Candidates)),
		Error:               snapshot.Error,
	}
	if !snapshot.ObservedAt.IsZero() {
		response.ObservedAt = snapshot.ObservedAt.Format(time.RFC3339Nano)
	}
	for _, candidate := range snapshot.Candidates {
		response.Candidates = append(response.Candidates, &EgressCandidate{
			Family:          candidate.Family,
			Interface:       egressInterfaceMessage(candidate.Interface),
			Eligible:        candidate.Eligible,
			Reasons:         append([]string(nil), candidate.Reasons...),
			RouteMetric:     candidate.RouteMetric,
			InterfaceMetric: candidate.InterfaceMetric,
		})
	}
	return response, nil
}

func egressFamilyMessage(family egress.FamilyStatus) *EgressFamilyStatus {
	return &EgressFamilyStatus{
		State:           family.State,
		Interface:       egressInterfaceMessage(family.Interface),
		Reason:          family.Reason,
		RouteMetric:     family.RouteMetric,
		InterfaceMetric: family.InterfaceMetric,
	}
}

func egressInterfaceMessage(iface *egress.Interface) *EgressInterface {
	if iface == nil {
		return nil
	}
	return &EgressInterface{
		Name:      iface.Name,
		Index:     iface.Index,
		Ipv6Index: iface.IPv6Index,
		Luid:      iface.LUID,
		Addresses: append([]string(nil), iface.Addresses...),
	}
}

// NewRoutingServer creates a statistics service with statistics manager.
func NewRoutingServer(router routing.Router, routingStats stats.Channel) RoutingServiceServer {
	return &routingServer{
		router:       router,
		routingStats: routingStats,
	}
}

func (s *routingServer) TestRoute(ctx context.Context, request *TestRouteRequest) (*RoutingContext, error) {
	if request.RoutingContext == nil {
		return nil, errors.New("Invalid routing request.")
	}
	route, err := s.router.PickRoute(AsRoutingContext(request.RoutingContext))
	if err != nil {
		return nil, err
	}
	if request.PublishResult && s.routingStats != nil {
		ctx, _ := context.WithTimeout(context.Background(), 4*time.Second)
		s.routingStats.Publish(ctx, route)
	}
	return AsProtobufMessage(request.FieldSelectors)(route), nil
}

func (s *routingServer) SubscribeRoutingStats(request *SubscribeRoutingStatsRequest, stream RoutingService_SubscribeRoutingStatsServer) error {
	if s.routingStats == nil {
		return errors.New("Routing statistics not enabled.")
	}
	genMessage := AsProtobufMessage(request.FieldSelectors)
	subscriber, err := stats.SubscribeRunnableChannel(s.routingStats)
	if err != nil {
		return err
	}
	defer stats.UnsubscribeClosableChannel(s.routingStats, subscriber)
	for {
		select {
		case value, ok := <-subscriber:
			if !ok {
				return errors.New("Upstream closed the subscriber channel.")
			}
			route, ok := value.(routing.Route)
			if !ok {
				return errors.New("Upstream sent malformed statistics.")
			}
			err := stream.Send(genMessage(route))
			if err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (s *routingServer) mustEmbedUnimplementedRoutingServiceServer() {}

type service struct {
	v *core.Instance
}

func (s *service) Register(server *grpc.Server) {
	common.Must(s.v.RequireFeatures(func(router routing.Router, stats stats.Manager) {
		rs := NewRoutingServer(router, nil)
		RegisterRoutingServiceServer(server, rs)

		// For compatibility purposes
		vCoreDesc := RoutingService_ServiceDesc
		vCoreDesc.ServiceName = "v2ray.core.app.router.command.RoutingService"
		server.RegisterService(&vCoreDesc, rs)
	}, false))
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		s := core.MustFromContext(ctx)
		return &service{v: s}, nil
	}))
}
