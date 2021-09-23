// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg_attr(not(unix), allow(unused_imports))]

use std::path::Path;

use futures::TryFutureExt;
#[cfg(unix)]
use tokio::net::UnixListener;
use tonic::{transport::Server, Request, Response, Status};

use signer::{
    signer_server::{Signer, SignerServer},
    AggregatePkRequest, AggregateResponse, AggregateSigRequest,
    CreateApkRequest, CreateApkResponse, GenerateKeysResponse, SignRequest,
    SignResponse, VerifyRequest, VerifyResponse,
};

mod signer;

#[derive(Default)]
pub struct MySign {}

#[tonic::async_trait]
impl Signer for MySign {
    async fn generate_keys(
        &self,
        request: Request<()>,
    ) -> Result<Response<GenerateKeysResponse>, Status> {
        let reply = GenerateKeysResponse {
            private_key: vec![],
            public_key: vec![],
        };
        Ok(Response::new(reply))
    }

    async fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let reply = SignResponse { response: None };
        Ok(Response::new(reply))
    }

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let reply = VerifyResponse { response: None };
        Ok(Response::new(reply))
    }

    async fn create_apk(
        &self,
        request: Request<CreateApkRequest>,
    ) -> Result<Response<CreateApkResponse>, Status> {
        let reply = CreateApkResponse { response: None };
        Ok(Response::new(reply))
    }

    async fn aggregate_pk(
        &self,
        request: Request<AggregatePkRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        let reply = AggregateResponse { response: None };
        Ok(Response::new(reply))
    }

    async fn aggregate_sig(
        &self,
        request: Request<AggregateSigRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        let reply = AggregateResponse { response: None };
        Ok(Response::new(reply))
    }
}

fn main() {}

#[cfg(not(unix))]
fn main() {
    panic!("Unix Domain Sockets can only be used on unix systems!");
}
