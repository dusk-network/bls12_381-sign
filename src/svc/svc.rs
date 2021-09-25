// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg_attr(not(unix), allow(unused_imports))]

// use std::path::Path;

// use futures::TryFutureExt;
// #[cfg(unix)]
// use tokio::net::UnixListener;
use tonic::{
    // transport::Server, IntoRequest,
    Request,
    Response,
    Status,
};

use crate::signer::create_apk_response::Apk::Apk;
use dusk_bls12_381_sign::{
    // Error,
    PublicKey,
    SecretKey,
    Signature,
    APK,
};
use signer::{
    aggregate_response::Agg, sign_response::Sig, signer_server::Signer,
    verify_response::Ver, AggregatePkRequest, AggregateResponse,
    AggregateSigRequest, CreateApkRequest, CreateApkResponse,
    GenerateKeysResponse, SignRequest, SignResponse, VerifyRequest,
    VerifyResponse,
};
use std::convert::TryFrom;

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

        // construct the gRPC response from the key and return it
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

        // check the length of the secret key and convert to a fixed length array
        let sk = <&[u8; SecretKey::serialized_size()]>::try_from(
            req.private_key.as_slice(),
        );
        if sk.is_err() {
            return Err(Status::invalid_argument(
                "provided secret key is wrong length",
            ));
        }
        let sk = sk.unwrap();
        // create a new secret key from the provided bytes
        let sk = SecretKey::from_bytes(sk);
        if sk.is_err() {
            return Err(Status::invalid_argument("error decoding secret key"));
        }
        let sk = sk.unwrap();

        // check the length of the public key and convert to fixed length array
        let pk = <&[u8; PublicKey::serialized_size()]>::try_from(
            req.public_key.as_slice(),
        );
        if pk.is_err() {
            return Err(Status::invalid_argument(
                "provided public key is wrong length",
            ));
        }
        let pk = pk.unwrap();
        // create a new public key from the provided bytes
        let pk = PublicKey::from_bytes(pk);
        if pk.is_err() {
            return Err(Status::invalid_argument("error decoding public key"));
        }
        let pk = pk.unwrap();

        // sign the message
        let res = Sig::Signature(
            sk.sign(&pk, req.message.as_slice()).to_bytes().to_vec(),
        );

        // return the signature wrapped in the response type
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

        // check length of public key and convert to fixed length array
        let apk =
            <&[u8; PublicKey::serialized_size()]>::try_from(req.apk.as_slice());
        if apk.is_err() {
            return Err(Status::invalid_argument(
                "provided (aggregated) public key is wrong length",
            ));
        }
        let apk = apk.unwrap();
        // create new aggregated public key from provided bytes
        let apk = APK::from_bytes(apk);
        if apk.is_err() {
            return Err(Status::invalid_argument(
                "(aggregated) public key failed to decode",
            ));
        }
        let apk = apk.unwrap();

        // check length of signature and convert to fixed length array
        let sig = <&[u8; Signature::serialized_size()]>::try_from(
            req.signature.as_slice(),
        );
        if sig.is_err() {
            return Err(Status::invalid_argument(
                "provided (aggregated) public key is wrong length",
            ));
        }
        let sig = sig.unwrap();
        // create signature from the provided bytes
        let sig = Signature::from_bytes(sig);
        if sig.is_err() {
            return Err(Status::invalid_argument(
                "provided signature is in invalid form",
            ));
        }
        let sig = sig.unwrap();

        // verify the message matches the signature and the signature matches the
        // given public key
        let res = apk.verify(&sig, &req.message);

        // return whether the verification returned no error
        Ok(Response::new(VerifyResponse {
            ver: Some(Ver::Valid(!res.is_err())),
        }))
    }

    async fn create_apk(
        &self,
        request: Request<CreateApkRequest>,
    ) -> Result<Response<CreateApkResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();

        // check the length of the public key and convert to fixed length array
        let pk = <&[u8; PublicKey::serialized_size()]>::try_from(
            req.public_key.as_slice(),
        );
        if pk.is_err() {
            return Err(Status::invalid_argument(
                "provided public key is wrong length",
            ));
        }
        let pk = pk.unwrap();
        // create a new public key from the provided bytes
        let pk = PublicKey::from_bytes(pk);
        if pk.is_err() {
            return Err(Status::invalid_argument("error decoding public key"));
        }
        let pk = pk.unwrap();

        // convert public key to aggregated public key and return it
        let apk = APK::from(&pk);
        Ok(Response::new(CreateApkResponse {
            apk: Some(Apk(apk.to_bytes().to_vec())),
        }))
    }

    async fn aggregate_pk(
        &self,
        request: Request<AggregatePkRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();

        // check length of public key and convert to fixed length array
        let apk =
            <&[u8; PublicKey::serialized_size()]>::try_from(req.apk.as_slice());
        if apk.is_err() {
            return Err(Status::invalid_argument(
                "provided (aggregated) public key is wrong length",
            ));
        }
        let apk = apk.unwrap();

        // create new aggregated public key from provided bytes
        let apk = APK::from_bytes(apk);
        if apk.is_err() {
            return Err(Status::invalid_argument(
                "(aggregated) public key failed to decode",
            ));
        }
        let mut apk = apk.unwrap();

        // convert the raw bytes from the message to a collection of public keys
        let mut pks: Vec<PublicKey> = Vec::with_capacity(req.keys.len());
        for (i, key) in req.keys.iter().enumerate() {
            // check the length of the public key and convert to fixed length array
            let pk =
                <&[u8; PublicKey::serialized_size()]>::try_from(key.as_slice());
            if pk.is_err() {
                return Err(Status::invalid_argument(
                    "provided public key is wrong length",
                ));
            }
            let pk = pk.unwrap();
            // create a new public key from the provided bytes
            let pk = PublicKey::from_bytes(pk);
            if pk.is_err() {
                return Err(Status::invalid_argument(
                    "error decoding public key",
                ));
            }
            let pk = pk.unwrap();

            // append to collection of PublicKeys
            pks[i] = pk;
        }

        // aggregate the keys
        apk.aggregate(&pks.as_slice());

        // convert public key to aggregated public key and return it
        let apb = apk.to_bytes();
        Ok(Response::new(AggregateResponse {
            agg: Some(Agg::Code(apb.into())),
        }))
    }

    async fn aggregate_sig(
        &self,
        request: Request<AggregateSigRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();

        // check length of signature and convert to fixed length array
        let sig = <&[u8; Signature::serialized_size()]>::try_from(
            req.signature.as_slice(),
        );
        if sig.is_err() {
            return Err(Status::invalid_argument(
                "provided signature is wrong length",
            ));
        }
        let sig = sig.unwrap();
        // create new aggregated public key from provided bytes
        let sig = Signature::from_bytes(sig);
        if sig.is_err() {
            return Err(Status::invalid_argument("signature failed to decode"));
        }
        let sig = sig.unwrap();

        // convert the raw bytes from the message to a collection of signatures
        let mut sigs: Vec<Signature> = Vec::with_capacity(req.signatures.len());
        for (i, si) in req.signatures.iter().enumerate() {
            // check the length of the signature and convert to fixed length array
            let s =
                <&[u8; Signature::serialized_size()]>::try_from(si.as_slice());
            if s.is_err() {
                return Err(Status::invalid_argument(
                    "provided signature is wrong length",
                ));
            }
            let s = s.unwrap();
            // create a new signature from the provided bytes
            let s = Signature::from_bytes(s);
            if s.is_err() {
                return Err(Status::invalid_argument(
                    "error decoding public key",
                ));
            }
            let s = s.unwrap();

            // append to collection of Signature
            sigs[i] = s;
        }

        // aggregate the signatures
        sig.aggregate(&sigs.as_slice());

        // convert aggregate signature to bytes and return
        let sigb = sig.to_bytes();
        Ok(Response::new(AggregateResponse {
            agg: Some(Agg::Code(sigb.into())),
        }))
    }
}

fn main() {}

#[cfg(not(unix))]
fn main() {
    panic!("Unix Domain Sockets can only be used on unix systems!");
}
