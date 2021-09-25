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

use dusk_bls12_381_sign::{Error, PublicKey, SecretKey, Signature, APK};
use signer::{
    sign_response::Sig,
    signer_server::{Signer, SignerServer},
    verify_response::Ver,
    AggregatePkRequest, AggregateResponse, AggregateSigRequest,
    CreateApkRequest, CreateApkResponse, GenerateKeysResponse, SignRequest,
    SignResponse, VerifyRequest, VerifyResponse,
};
use std::convert::{TryFrom, TryInto};

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
        let req = request.get_ref();
        // read in the secret key
        let sk = <&[u8; SecretKey::serialized_size()]>::try_from(
            req.private_key.as_slice(),
        );
        if sk.is_err() {
            return Err(Status::invalid_argument(
                "provided secret key is wrong length",
            ));
        }
        let sk = sk.unwrap();
        let sk = SecretKey::from_bytes(sk);
        if sk.is_err() {
            return Err(Status::invalid_argument("error decoding secret key"));
        }
        let sk = sk.unwrap();
        let pk = <&[u8; PublicKey::serialized_size()]>::try_from(
            req.public_key.as_slice(),
        );
        if pk.is_err() {
            return Err(Status::invalid_argument(
                "provided public key is wrong length",
            ));
        }
        let pk = pk.unwrap();
        let pk = PublicKey::from_bytes(pk);
        if pk.is_err() {
            return Err(Status::invalid_argument("error decoding public key"));
        }
        let res = Sig::Signature(
            sk.sign(&pk.unwrap(), req.message.as_slice())
                .to_bytes()
                .to_vec(),
        );
        Ok(Response::new(SignResponse {
            sig: Option::Some(res),
        }))
    }

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        let apk =
            <&[u8; PublicKey::serialized_size()]>::try_from(req.apk.as_slice());
        if apk.is_err() {
            return Err(Status::invalid_argument(
                "provided (aggregated) public key is wrong length",
            ));
        }
        let apk = apk.unwrap();
        let apk = APK::from_bytes(apk);
        if apk.is_err() {
            return Err(Status::invalid_argument(
                "(aggregated) public key failed to decode",
            ));
        }
        let apk = apk.unwrap();
        let sig = <&[u8; Signature::serialized_size()]>::try_from(
            req.signature.as_slice(),
        );
        if sig.is_err() {
            return Err(Status::invalid_argument(
                "provided (aggregated) public key is wrong length",
            ));
        }
        let sig = sig.unwrap();
        let sig = Signature::from_bytes(sig);
        if sig.is_err() {
            return Err(Status::invalid_argument(
                "provided signature is in invalid form",
            ));
        }
        let sig = sig.unwrap();
        let res = apk.verify(&sig, &req.message);
        if !res.is_ok() {
            return Err(Status::invalid_argument(
                "provided signature fails verification",
            ));
        }
        Ok(Response::new(VerifyResponse {
            ver: Some(Ver::Valid(true)),
        }))
    }

    async fn create_apk(
        &self,
        request: Request<CreateApkRequest>,
    ) -> Result<Response<CreateApkResponse>, Status> {
        let reply = CreateApkResponse { apk: None };
        Ok(Response::new(reply))
    }

    async fn aggregate_pk(
        &self,
        request: Request<AggregatePkRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        let reply = AggregateResponse { agg: None };
        Ok(Response::new(reply))
    }

    async fn aggregate_sig(
        &self,
        request: Request<AggregateSigRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        let reply = AggregateResponse { agg: None };
        Ok(Response::new(reply))
    }
}

fn main() {}

#[cfg(not(unix))]
fn main() {
    panic!("Unix Domain Sockets can only be used on unix systems!");
}
