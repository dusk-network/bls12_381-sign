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
use verify_response::Ver::Valid;

#[derive(Default)]
pub struct MySign {}

// The following macros are written to minimize memory handling with [core::mem::transmute], and by
// early return on error from the calling function to reduce repeated match branches that are
// basically all the same

#[macro_export]
macro_rules! slice_as_array_transmute {
    ($slice:expr) => {
        ::core::mem::transmute($slice)
    };
}

#[macro_export]
macro_rules! slice_as {
    ($slice:expr, $wrapper:ty ) => {{
        unsafe fn this_transmute(
            xs: &[u8],
        ) -> &[u8; <$wrapper>::serialized_size()] {
            slice_as_array_transmute!(xs.as_ptr())
        }

        let s: &[u8] = $slice;
        if s.len() != <$wrapper>::serialized_size() {
            return Err(Status::invalid_argument(
                "provided vector is wrong length",
            ));
        } else {
            match <$wrapper>::from_bytes(unsafe { this_transmute(s) }) {
                Ok(v) => v,
                Err(_) => {
                    return Err(Status::invalid_argument(
                        "unable to convert to type",
                    ))
                }
            }
        }
    }};
}

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
        let sk = slice_as!(req.secret_key.as_slice(), SecretKey);
        let pk = slice_as!(req.public_key.as_slice(), PublicKey);
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
        let apk = slice_as!(req.apk.as_slice(), APK);
        let sig = slice_as!(req.signature.as_slice(), Signature);

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
        let apk = slice_as!(req.public_key.as_slice(), APK);
        // attempt to convert public key to aggregated public key
        let apk = match APK::from_bytes(&apk.to_bytes()) {
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
        let mut apk = slice_as!(req.apk.as_slice(), APK);

        // convert the raw bytes from the message to a collection of public keys
        let mut pks: Vec<PublicKey> = Vec::with_capacity(req.keys.len());
        for (i, key) in req.keys.iter().enumerate() {
            // convert bytes to PublicKey
            let pk = slice_as!(key.as_slice(), PublicKey);
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
        let sig = slice_as!(req.signature.as_slice(), Signature);

        // convert the raw bytes from the message to a collection of signatures
        let mut sigs: Vec<Signature> = Vec::with_capacity(req.signatures.len());
        for (i, si) in req.signatures.iter().enumerate() {
            // add to collection of Signature
            sigs[i] = slice_as!(si, Signature);
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
