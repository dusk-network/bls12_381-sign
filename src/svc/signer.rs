#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenerateKeysRequest {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenerateKeysResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub secret_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub secret_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub message: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignResponse {
    #[prost(oneof = "sign_response::Sig", tags = "1, 2")]
    pub sig: ::core::option::Option<sign_response::Sig>,
}
/// Nested message and enum types in `SignResponse`.
pub mod sign_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Sig {
        #[prost(bytes, tag = "1")]
        Signature(::prost::alloc::vec::Vec<u8>),
        #[prost(enumeration = "super::Error", tag = "2")]
        Error(i32),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VerifyRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub apk: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub message: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VerifyResponse {
    #[prost(oneof = "verify_response::Ver", tags = "1, 2")]
    pub ver: ::core::option::Option<verify_response::Ver>,
}
/// Nested message and enum types in `VerifyResponse`.
pub mod verify_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Ver {
        #[prost(bool, tag = "1")]
        Valid(bool),
        #[prost(enumeration = "super::Error", tag = "2")]
        Error(i32),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateApkRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateApkResponse {
    #[prost(oneof = "create_apk_response::Apk", tags = "1, 2")]
    pub apk: ::core::option::Option<create_apk_response::Apk>,
}
/// Nested message and enum types in `CreateAPKResponse`.
pub mod create_apk_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Apk {
        #[prost(bytes, tag = "1")]
        Apk(::prost::alloc::vec::Vec<u8>),
        #[prost(enumeration = "super::Error", tag = "2")]
        Error(i32),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AggregatePkRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub apk: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub keys: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AggregateResponse {
    #[prost(oneof = "aggregate_response::Agg", tags = "1, 2")]
    pub agg: ::core::option::Option<aggregate_response::Agg>,
}
/// Nested message and enum types in `AggregateResponse`.
pub mod aggregate_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Agg {
        #[prost(bytes, tag = "1")]
        Code(::prost::alloc::vec::Vec<u8>),
        #[prost(enumeration = "super::Error", tag = "2")]
        Error(i32),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AggregateSigRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub signatures: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum Error {
    BlsInvalidBytes = 0,
    BlsVerificationFailed = 1,
    Unknown = 2,
}
#[doc = r" Generated client implementations."]
pub mod signer_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    #[derive(Debug, Clone)]
    pub struct SignerClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl SignerClient<tonic::transport::Channel> {
        #[doc = r" Attempt to create a new client by connecting to a given endpoint."]
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> SignerClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + Send + Sync + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> SignerClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T:
                tonic::codegen::Service<
                    http::Request<tonic::body::BoxBody>,
                    Response = http::Response<
                        <T as tonic::client::GrpcService<
                            tonic::body::BoxBody,
                        >>::ResponseBody,
                    >,
                >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + Send + Sync,
        {
            SignerClient::new(InterceptedService::new(inner, interceptor))
        }
        #[doc = r" Compress requests with `gzip`."]
        #[doc = r""]
        #[doc = r" This requires the server to support it otherwise it might respond with an"]
        #[doc = r" error."]
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        #[doc = r" Enable decompressing responses with `gzip`."]
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
        }
        pub async fn generate_keys(
            &mut self,
            request: impl tonic::IntoRequest<super::GenerateKeysRequest>,
        ) -> Result<tonic::Response<super::GenerateKeysResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/signer.Signer/GenerateKeys",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn sign(
            &mut self,
            request: impl tonic::IntoRequest<super::SignRequest>,
        ) -> Result<tonic::Response<super::SignResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/signer.Signer/Sign");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn verify(
            &mut self,
            request: impl tonic::IntoRequest<super::VerifyRequest>,
        ) -> Result<tonic::Response<super::VerifyResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/signer.Signer/Verify");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn create_apk(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateApkRequest>,
        ) -> Result<tonic::Response<super::CreateApkResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/signer.Signer/CreateAPK",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn aggregate_pk(
            &mut self,
            request: impl tonic::IntoRequest<super::AggregatePkRequest>,
        ) -> Result<tonic::Response<super::AggregateResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/signer.Signer/AggregatePK",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn aggregate_sig(
            &mut self,
            request: impl tonic::IntoRequest<super::AggregateSigRequest>,
        ) -> Result<tonic::Response<super::AggregateResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/signer.Signer/AggregateSig",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}
#[doc = r" Generated server implementations."]
pub mod signer_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    #[doc = "Generated trait containing gRPC methods that should be implemented for use with SignerServer."]
    #[async_trait]
    pub trait Signer: Send + Sync + 'static {
        async fn generate_keys(
            &self,
            request: tonic::Request<super::GenerateKeysRequest>,
        ) -> Result<tonic::Response<super::GenerateKeysResponse>, tonic::Status>;
        async fn sign(
            &self,
            request: tonic::Request<super::SignRequest>,
        ) -> Result<tonic::Response<super::SignResponse>, tonic::Status>;
        async fn verify(
            &self,
            request: tonic::Request<super::VerifyRequest>,
        ) -> Result<tonic::Response<super::VerifyResponse>, tonic::Status>;
        async fn create_apk(
            &self,
            request: tonic::Request<super::CreateApkRequest>,
        ) -> Result<tonic::Response<super::CreateApkResponse>, tonic::Status>;
        async fn aggregate_pk(
            &self,
            request: tonic::Request<super::AggregatePkRequest>,
        ) -> Result<tonic::Response<super::AggregateResponse>, tonic::Status>;
        async fn aggregate_sig(
            &self,
            request: tonic::Request<super::AggregateSigRequest>,
        ) -> Result<tonic::Response<super::AggregateResponse>, tonic::Status>;
    }
    #[derive(Debug)]
    pub struct SignerServer<T: Signer> {
        inner: _Inner<T>,
        accept_compression_encodings: (),
        send_compression_encodings: (),
    }
    struct _Inner<T>(Arc<T>);
    impl<T: Signer> SignerServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for SignerServer<T>
    where
        T: Signer,
        B: Body + Send + Sync + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = Never;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/signer.Signer/GenerateKeys" => {
                    #[allow(non_camel_case_types)]
                    struct GenerateKeysSvc<T: Signer>(pub Arc<T>);
                    impl<T: Signer>
                        tonic::server::UnaryService<super::GenerateKeysRequest>
                        for GenerateKeysSvc<T>
                    {
                        type Response = super::GenerateKeysResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GenerateKeysRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).generate_keys(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings =
                        self.accept_compression_encodings;
                    let send_compression_encodings =
                        self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GenerateKeysSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/signer.Signer/Sign" => {
                    #[allow(non_camel_case_types)]
                    struct SignSvc<T: Signer>(pub Arc<T>);
                    impl<T: Signer>
                        tonic::server::UnaryService<super::SignRequest>
                        for SignSvc<T>
                    {
                        type Response = super::SignResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SignRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut =
                                async move { (*inner).sign(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings =
                        self.accept_compression_encodings;
                    let send_compression_encodings =
                        self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = SignSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/signer.Signer/Verify" => {
                    #[allow(non_camel_case_types)]
                    struct VerifySvc<T: Signer>(pub Arc<T>);
                    impl<T: Signer>
                        tonic::server::UnaryService<super::VerifyRequest>
                        for VerifySvc<T>
                    {
                        type Response = super::VerifyResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::VerifyRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut =
                                async move { (*inner).verify(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings =
                        self.accept_compression_encodings;
                    let send_compression_encodings =
                        self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = VerifySvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/signer.Signer/CreateAPK" => {
                    #[allow(non_camel_case_types)]
                    struct CreateAPKSvc<T: Signer>(pub Arc<T>);
                    impl<T: Signer>
                        tonic::server::UnaryService<super::CreateApkRequest>
                        for CreateAPKSvc<T>
                    {
                        type Response = super::CreateApkResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::CreateApkRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).create_apk(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings =
                        self.accept_compression_encodings;
                    let send_compression_encodings =
                        self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = CreateAPKSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/signer.Signer/AggregatePK" => {
                    #[allow(non_camel_case_types)]
                    struct AggregatePKSvc<T: Signer>(pub Arc<T>);
                    impl<T: Signer>
                        tonic::server::UnaryService<super::AggregatePkRequest>
                        for AggregatePKSvc<T>
                    {
                        type Response = super::AggregateResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::AggregatePkRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).aggregate_pk(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings =
                        self.accept_compression_encodings;
                    let send_compression_encodings =
                        self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = AggregatePKSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/signer.Signer/AggregateSig" => {
                    #[allow(non_camel_case_types)]
                    struct AggregateSigSvc<T: Signer>(pub Arc<T>);
                    impl<T: Signer>
                        tonic::server::UnaryService<super::AggregateSigRequest>
                        for AggregateSigSvc<T>
                    {
                        type Response = super::AggregateResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::AggregateSigRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move {
                                (*inner).aggregate_sig(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings =
                        self.accept_compression_encodings;
                    let send_compression_encodings =
                        self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = AggregateSigSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(empty_body())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: Signer> Clone for SignerServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: Signer> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: Signer> tonic::transport::NamedService for SignerServer<T> {
        const NAME: &'static str = "signer.Signer";
    }
}
