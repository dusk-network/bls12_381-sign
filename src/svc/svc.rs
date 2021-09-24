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
use tonic::{transport::Server, IntoRequest, Request, Response, Status};

use crate::signer::sign_response;
use bls12381sig::{Error, PublicKey, SecretKey, Signature, APK};
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
    // BLS12-381 Signer service implementation

    // Generate a new BLS12-381 key pair
    async fn generate_keys(
        &self,
        _request: Request<()>,
    ) -> Result<Response<GenerateKeysResponse>, Status> {
        // get a new random secret key from system entropy
        let sk = SecretKey::new(&mut rand_core::OsRng);
        // construct the gRPC response from the key and return the response
        Ok(Response::new(GenerateKeysResponse {
            private_key: sk.to_bytes().to_vec(),
            public_key: PublicKey::from(&sk).to_bytes().to_vec(),
        }))
    }

    // Sign a message using a provided BLS12-381 key pair
    async fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        // access the request parameters
        let req: SignRequest = request.into_request().into_inner();
        // read in the secret key
        let sk = req.private_key;
        // read in the public key
        let pk = req.public_key.as_slice();
        // read in the message to be signed
        let msg = req.message.as_slice();

        let mut sk = SecretKey::from_bytes(sk.to_vec().)
        // let pk = PublicKey::from_bytes(req.public_key.to_bytes());
        // let msg = req.message;
        // sign the message
        // let sig = SignResponse {
        // response: sk.sign(&pk, &msg).to_bytes(),
        // };
        Ok(Response::new(SignResponse { response: None }))
    }

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        // let req = request.into_request().into_inner();

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
