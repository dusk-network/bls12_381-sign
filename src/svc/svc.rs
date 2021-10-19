// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![feature(test)]
#![cfg_attr(not(unix), allow(unused_imports))]

mod signer;
#[cfg(feature = "std")]
#[cfg(unix)]
mod unix;
use crate::signer::BlsSigner;

#[cfg(feature = "std")]
tonic::include_proto!("signer");

#[cfg(feature = "std")]
use {
    futures::TryFutureExt,
    signer_server::{Signer, SignerServer},
    std::process::exit,
    tokio::net::UnixListener,
    tonic::{transport::Server, Request, Response, Status},
};

#[cfg(feature = "std")]
#[tonic::async_trait]
impl Signer for BlsSigner {
    /// BLS12-381 Signer service implementation

    async fn generate_keys(
        &self,
        _request: Request<GenerateKeysRequest>,
    ) -> Result<Response<GenerateKeysResponse>, Status> {
        self.generate_keys_sync()
    }

    async fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        self.sign_sync(&request).await
    }

    /// Verify a BLS12-381 signature on a message with a given public key
    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        self.verify_sync(&request).await
    }

    /// Create an aggregated public key from a public key
    async fn create_apk(
        &self,
        request: Request<CreateApkRequest>,
    ) -> Result<Response<CreateApkResponse>, Status> {
        self.create_apk_sync(&request).await
    }

    /// Aggregate a collection of public keys to an aggregated public key
    async fn aggregate_pk(
        &self,
        request: Request<AggregatePkRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        self.aggregate_pk_sync(&request).await
    }

    /// Aggregate a collection of signatures into an aggregated signature
    async fn aggregate_sig(
        &self,
        request: Request<AggregateSigRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        self.aggregate_sig_sync(&request).await
    }
}

#[cfg(feature = "std")]
extern crate ctrlc;

/// Default UDS path that Rusk GRPC-server will connect to.
pub const SOCKET_PATH: &str = "/tmp/bls12381svc.sock";

#[cfg(feature = "std")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let path = "127.0.0.1:9476".parse().unwrap();
    let path = SOCKET_PATH;
    let uds = UnixListener::bind(path)?;

    // adding our service to our server.
    let signeur = BlsSigner::default();

    let signer = SignerServer::new(signeur);

    let incoming = {
        async_stream::stream! {
            loop{
                let item = uds.accept().map_ok(|(st, _)| unix::UnixStream(st)).await;
                yield item;
            };
        }
    };

    ctrlc::set_handler(move || {
        exit(0);
    })?;
    Server::builder()
        // .accept_http1(false)
        .add_service(signer)
        // .serve(path)
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    panic!("Unix Domain Sockets can only be used on unix systems!");
}

#[cfg(not(feature = "std"))]
fn main() {
    panic!("std feature required");
}
