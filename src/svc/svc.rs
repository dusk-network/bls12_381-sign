// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg_attr(not(unix), allow(unused_imports))]

use tonic::{transport::Server, Request, Response, Status};

tonic::include_proto!("bls12381sig");

use aggregate_response::Agg::Code;
use create_apk_response::Apk::Apk;
use dusk_bls12_381_sign::{PublicKey, SecretKey, Signature, APK};
use sign_response::Sig::Signature as ResponseSignature;
use signer_server::{Signer, SignerServer};
use std::convert::TryFrom;
use verify_response::Ver::Valid;

#[derive(Default)]
pub struct MySign {}

#[tonic::async_trait]
impl Signer for MySign {
    /// BLS12-381 Signer service implementation

    /// Generate a new BLS12-381 key pair
    async fn generate_keys(
        &self,
        _request: Request<GenerateKeysRequest>,
    ) -> Result<Response<GenerateKeysResponse>, Status> {
        // get a new random secret key from system entropy
        let sk = SecretKey::new(&mut rand_core::OsRng);

        // construct the gRPC response from the key and return it
        Ok(Response::new(GenerateKeysResponse {
            secret_key: sk.to_bytes().to_vec(),
            public_key: PublicKey::from(&sk).to_bytes().to_vec(),
        }))
    }

    /// Sign a message using a provided BLS12-381 key pair
    async fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();

        // check the length of the secret key and convert to a fixed length array
        let sk = match <&[u8; SecretKey::serialized_size()]>::try_from(
            req.secret_key.as_slice(),
        ) {
            Ok(sk) => sk,
            Err(_) => {
                return Err(Status::invalid_argument(
                    "provided secret key is wrong length",
                ))
            }
        };

        // create a new secret key from the provided bytes
        // let sk = SecretKey::from_bytes(sk);
        let sk = match SecretKey::from_bytes(sk) {
            Ok(sk) => sk,
            Err(_) => {
                return Err(Status::invalid_argument(
                    "error decoding secret key",
                ))
            }
        };

        // check the length of the public key and convert to fixed length array
        let pk = match <&[u8; PublicKey::serialized_size()]>::try_from(
            req.public_key.as_slice(),
        ) {
            Ok(pk) => pk,
            Err(e) => return Err(Status::invalid_argument(e.to_string())),
        };

        // create a new public key from the provided bytes
        let pk = match PublicKey::from_bytes(pk) {
            Ok(pk) => pk,
            Err(e) => return Err(Status::invalid_argument(e.to_string())),
        };

        // sign the message
        let res = ResponseSignature(
            sk.sign(&pk, req.message.as_slice()).to_bytes().to_vec(),
        );

        // return the signature wrapped in the response type
        Ok(Response::new(SignResponse {
            sig: Option::Some(res),
        }))
    }

    /// Verify a BLS12-381 signature on a message with a given public key
    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();

        // check length of public key and convert to fixed length array
        let apk = match <&[u8; PublicKey::serialized_size()]>::try_from(
            req.apk.as_slice(),
        ) {
            Ok(req) => req,
            Err(e) => return Err(Status::invalid_argument(e.to_string())),
        };

        // create new aggregated public key from provided bytes
        let apk = match APK::from_bytes(apk) {
            Ok(apk) => apk,
            Err(e) => return Err(Status::invalid_argument(e.to_string())),
        };

        // check length of signature and convert to fixed length array
        let sig = match <&[u8; Signature::serialized_size()]>::try_from(
            req.signature.as_slice(),
        ) {
            Ok(sig) => sig,
            Err(e) => return Err(Status::invalid_argument(e.to_string())),
        };

        // create signature from the provided bytes
        let sig = match Signature::from_bytes(sig) {
            Ok(sig) => sig,
            Err(e) => return Err(Status::invalid_argument(e.to_string())),
        };

        // verify the message matches the signature and the signature matches the
        // given public key
        let res = apk.verify(&sig, &req.message);

        // return whether the verification returned no error
        Ok(Response::new(VerifyResponse {
            ver: Some(Valid(!res.is_err())),
        }))
    }

    /// Create an aggregated public key from a public key
    async fn create_apk(
        &self,
        request: Request<CreateApkRequest>,
    ) -> Result<Response<CreateApkResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();

        // check the length of the public key and convert to fixed length array
        let pk = match <&[u8; PublicKey::serialized_size()]>::try_from(
            req.public_key.as_slice(),
        ) {
            Ok(pk) => pk,
            Err(e) => return Err(Status::invalid_argument(e.to_string())),
        };

        // create a new public key from the provided bytes
        let pk = match PublicKey::from_bytes(pk) {
            Ok(pk) => pk,
            Err(e) => return Err(Status::invalid_argument(e.to_string())),
        };

        // convert public key to aggregated public key and return it
        let apk = match APK::from_bytes(&pk.to_bytes()) {
            Ok(apk) => apk,
            Err(e) => return Err(Status::invalid_argument(e.to_string())),
        };
        Ok(Response::new(CreateApkResponse {
            apk: Some(Apk(apk.to_bytes().to_vec())),
        }))
    }

    /// Aggregate a collection of public keys to an aggregated public key
    async fn aggregate_pk(
        &self,
        request: Request<AggregatePkRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();

        // check length of public key and convert to fixed length array
        let apk = match <&[u8; PublicKey::serialized_size()]>::try_from(
            req.apk.as_slice(),
        ) {
            Ok(apk) => apk,
            Err(e) => return Err(Status::invalid_argument(e.to_string())),
        };

        // create new aggregated public key from provided bytes
        let mut apk = match APK::from_bytes(apk) {
            Ok(apk) => apk,
            Err(e) => return Err(Status::invalid_argument(e.to_string())),
        };

        // convert the raw bytes from the message to a collection of public keys
        let mut pks: Vec<PublicKey> = Vec::with_capacity(req.keys.len());
        for (i, key) in req.keys.iter().enumerate() {
            // check the length of the public key and convert to fixed length array
            let pk = match <&[u8; PublicKey::serialized_size()]>::try_from(
                key.as_slice(),
            ) {
                Ok(pk) => pk,
                Err(e) => return Err(Status::invalid_argument(e.to_string())),
            };
            // create a new public key from the provided bytes
            let pk = match PublicKey::from_bytes(pk) {
                Ok(pk) => pk,
                Err(e) => return Err(Status::invalid_argument(e.to_string())),
            };

            // add to collection of PublicKeys
            pks[i] = pk;
        }

        // aggregate the keys
        apk.aggregate(&pks.as_slice());

        // convert public key to aggregated public key and return it
        Ok(Response::new(AggregateResponse {
            agg: Some(Code(apk.to_bytes().into())),
        }))
    }

    /// Aggregate a collection of signatures into an aggregated signature
    async fn aggregate_sig(
        &self,
        request: Request<AggregateSigRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();

        // check length of signature and convert to fixed length array
        let sig = match <&[u8; Signature::serialized_size()]>::try_from(
            req.signature.as_slice(),
        ) {
            Ok(sig) => sig,
            Err(e) => return Err(Status::invalid_argument(e.to_string())),
        };

        // create new aggregated signature from provided bytes
        let sig = match Signature::from_bytes(sig) {
            Ok(sig) => sig,
            Err(e) => return Err(Status::invalid_argument(e.to_string())),
        };

        // convert the raw bytes from the message to a collection of signatures
        let mut sigs: Vec<Signature> = Vec::with_capacity(req.signatures.len());
        for (i, si) in req.signatures.iter().enumerate() {
            // check the length of the signature and convert to fixed length array
            let s = match <&[u8; Signature::serialized_size()]>::try_from(
                si.as_slice(),
            ) {
                Ok(s) => s,
                Err(e) => return Err(Status::invalid_argument(e.to_string())),
            };
            // create a new signature from the provided bytes
            let s = match Signature::from_bytes(s) {
                Ok(s) => s,
                Err(e) => return Err(Status::invalid_argument(e.to_string())),
            };

            // add to collection of Signature
            sigs[i] = s;
        }

        // aggregate the signatures
        sig.aggregate(&sigs.as_slice());

        // convert aggregate signature to bytes and return
        Ok(Response::new(AggregateResponse {
            agg: Some(Code(sig.to_bytes().into())),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // defining address for our service
    let addr = "127.0.0.1:9156".parse().unwrap();
    // creating a service
    let signeur = MySign::default();
    println!("Server listening on {}", addr);
    // adding our service to our server.
    Server::builder()
        .add_service(SignerServer::new(signeur))
        .serve(addr)
        .await?;
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    panic!("Unix Domain Sockets can only be used on unix systems!");
}
