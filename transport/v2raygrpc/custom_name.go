package v2raygrpc

import (
	"context"

	"google.golang.org/grpc"
)

type GunService interface {
	Context() context.Context
	Send(*Hunk) error
	Recv() (*Hunk, error)
}

type GunMultiService interface {
	Context() context.Context
	Send(hunk *MultiHunk) error
	Recv() (*MultiHunk, error)
}

func ServerDesc(name string) grpc.ServiceDesc {
	return grpc.ServiceDesc{
		ServiceName: name,
		HandlerType: (*GunServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Tun",
				Handler:       _GunService_Tun_Handler,
				ServerStreams: true,
				ClientStreams: true,
			},
			{
				StreamName:    "TunMulti",
				Handler:       _GunService_TunMulti_Handler,
				ServerStreams: true,
				ClientStreams: true,
			},
		},
		Metadata: "gun.proto",
	}
}

func (c *gunServiceClient) TunCustomName(ctx context.Context, name string, opts ...grpc.CallOption) (GunService_TunClient, error) {
	stream, err := c.cc.NewStream(ctx, &ServerDesc(name).Streams[0], "/"+name+"/Tun", opts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[Hunk, Hunk]{ClientStream: stream}
	return x, nil
}

func (c *gunServiceClient) TunMultiCustomName(ctx context.Context, name string, opts ...grpc.CallOption) (GunService_TunMultiClient, error) {
	stream, err := c.cc.NewStream(ctx, &ServerDesc(name).Streams[1], "/"+name+"/TunMulti", opts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[MultiHunk, MultiHunk]{ClientStream: stream}
	return x, nil
}

var _ GunServiceCustomNameClient = (*gunServiceClient)(nil)

type GunServiceCustomNameClient interface {
	TunCustomName(ctx context.Context, name string, opts ...grpc.CallOption) (GunService_TunClient, error)
	TunMultiCustomName(ctx context.Context, name string, opts ...grpc.CallOption) (GunService_TunMultiClient, error)
	Tun(ctx context.Context, opts ...grpc.CallOption) (GunService_TunClient, error)
	TunMulti(ctx context.Context, opts ...grpc.CallOption) (GunService_TunMultiClient, error)
}

func RegisterGunServiceCustomNameServer(s *grpc.Server, srv GunServiceServer, name string) {
	desc := ServerDesc(name)
	s.RegisterService(&desc, srv)
}
