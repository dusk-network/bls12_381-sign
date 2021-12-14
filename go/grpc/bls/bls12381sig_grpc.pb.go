// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package bls

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// SignerClient is the client API for Signer service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SignerClient interface {
	GenerateKeys(ctx context.Context, in *GenerateKeysRequest, opts ...grpc.CallOption) (*GenerateKeysResponse, error)
	Sign(ctx context.Context, in *SignRequest, opts ...grpc.CallOption) (*SignResponse, error)
	Verify(ctx context.Context, in *VerifyRequest, opts ...grpc.CallOption) (*VerifyResponse, error)
	CreateAPK(ctx context.Context, in *CreateAPKRequest, opts ...grpc.CallOption) (*CreateAPKResponse, error)
	AggregatePK(ctx context.Context, in *AggregatePKRequest, opts ...grpc.CallOption) (*AggregateResponse, error)
	AggregateSig(ctx context.Context, in *AggregateSigRequest, opts ...grpc.CallOption) (*AggregateResponse, error)
}

type signerClient struct {
	cc grpc.ClientConnInterface
}

func NewSignerClient(cc grpc.ClientConnInterface) SignerClient {
	return &signerClient{cc}
}

func (c *signerClient) GenerateKeys(ctx context.Context, in *GenerateKeysRequest, opts ...grpc.CallOption) (*GenerateKeysResponse, error) {
	out := new(GenerateKeysResponse)
	err := c.cc.Invoke(ctx, "/signer.Signer/GenerateKeys", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *signerClient) Sign(ctx context.Context, in *SignRequest, opts ...grpc.CallOption) (*SignResponse, error) {
	out := new(SignResponse)
	err := c.cc.Invoke(ctx, "/signer.Signer/Sign", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *signerClient) Verify(ctx context.Context, in *VerifyRequest, opts ...grpc.CallOption) (*VerifyResponse, error) {
	out := new(VerifyResponse)
	err := c.cc.Invoke(ctx, "/signer.Signer/Verify", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *signerClient) CreateAPK(ctx context.Context, in *CreateAPKRequest, opts ...grpc.CallOption) (*CreateAPKResponse, error) {
	out := new(CreateAPKResponse)
	err := c.cc.Invoke(ctx, "/signer.Signer/CreateAPK", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *signerClient) AggregatePK(ctx context.Context, in *AggregatePKRequest, opts ...grpc.CallOption) (*AggregateResponse, error) {
	out := new(AggregateResponse)
	err := c.cc.Invoke(ctx, "/signer.Signer/AggregatePK", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *signerClient) AggregateSig(ctx context.Context, in *AggregateSigRequest, opts ...grpc.CallOption) (*AggregateResponse, error) {
	out := new(AggregateResponse)
	err := c.cc.Invoke(ctx, "/signer.Signer/AggregateSig", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SignerServer is the server API for Signer service.
// All implementations should embed UnimplementedSignerServer
// for forward compatibility
type SignerServer interface {
	GenerateKeys(context.Context, *GenerateKeysRequest) (*GenerateKeysResponse, error)
	Sign(context.Context, *SignRequest) (*SignResponse, error)
	Verify(context.Context, *VerifyRequest) (*VerifyResponse, error)
	CreateAPK(context.Context, *CreateAPKRequest) (*CreateAPKResponse, error)
	AggregatePK(context.Context, *AggregatePKRequest) (*AggregateResponse, error)
	AggregateSig(context.Context, *AggregateSigRequest) (*AggregateResponse, error)
}

// UnimplementedSignerServer should be embedded to have forward compatible implementations.
type UnimplementedSignerServer struct {
}

func (UnimplementedSignerServer) GenerateKeys(context.Context, *GenerateKeysRequest) (*GenerateKeysResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateKeys not implemented")
}
func (UnimplementedSignerServer) Sign(context.Context, *SignRequest) (*SignResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Sign not implemented")
}
func (UnimplementedSignerServer) Verify(context.Context, *VerifyRequest) (*VerifyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Verify not implemented")
}
func (UnimplementedSignerServer) CreateAPK(context.Context, *CreateAPKRequest) (*CreateAPKResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateAPK not implemented")
}
func (UnimplementedSignerServer) AggregatePK(context.Context, *AggregatePKRequest) (*AggregateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AggregatePK not implemented")
}
func (UnimplementedSignerServer) AggregateSig(context.Context, *AggregateSigRequest) (*AggregateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AggregateSig not implemented")
}

// UnsafeSignerServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SignerServer will
// result in compilation errors.
type UnsafeSignerServer interface {
	mustEmbedUnimplementedSignerServer()
}

func RegisterSignerServer(s grpc.ServiceRegistrar, srv SignerServer) {
	s.RegisterService(&Signer_ServiceDesc, srv)
}

func _Signer_GenerateKeys_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateKeysRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SignerServer).GenerateKeys(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/signer.Signer/GenerateKeys",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SignerServer).GenerateKeys(ctx, req.(*GenerateKeysRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Signer_Sign_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SignerServer).Sign(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/signer.Signer/Sign",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SignerServer).Sign(ctx, req.(*SignRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Signer_Verify_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerifyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SignerServer).Verify(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/signer.Signer/Verify",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SignerServer).Verify(ctx, req.(*VerifyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Signer_CreateAPK_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateAPKRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SignerServer).CreateAPK(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/signer.Signer/CreateAPK",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SignerServer).CreateAPK(ctx, req.(*CreateAPKRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Signer_AggregatePK_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AggregatePKRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SignerServer).AggregatePK(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/signer.Signer/AggregatePK",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SignerServer).AggregatePK(ctx, req.(*AggregatePKRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Signer_AggregateSig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AggregateSigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SignerServer).AggregateSig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/signer.Signer/AggregateSig",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SignerServer).AggregateSig(ctx, req.(*AggregateSigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Signer_ServiceDesc is the grpc.ServiceDesc for Signer service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Signer_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "signer.Signer",
	HandlerType: (*SignerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GenerateKeys",
			Handler:    _Signer_GenerateKeys_Handler,
		},
		{
			MethodName: "Sign",
			Handler:    _Signer_Sign_Handler,
		},
		{
			MethodName: "Verify",
			Handler:    _Signer_Verify_Handler,
		},
		{
			MethodName: "CreateAPK",
			Handler:    _Signer_CreateAPK_Handler,
		},
		{
			MethodName: "AggregatePK",
			Handler:    _Signer_AggregatePK_Handler,
		},
		{
			MethodName: "AggregateSig",
			Handler:    _Signer_AggregateSig_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "bls12381sig.proto",
}
